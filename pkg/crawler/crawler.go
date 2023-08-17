package crawler

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"
)

const mavenRepoURL = "https://repo.maven.apache.org/maven2/"

type Crawler struct {
	dir  string
	http *retryablehttp.Client

	rootUrl string
	wg      sync.WaitGroup
	urlCh   chan string
	limit   *semaphore.Weighted
}

type Option struct {
	Limit    int64
	RootUrl  string
	CacheDir string
}

func NewCrawler(opt Option) Crawler {
	client := retryablehttp.NewClient()
	client.Logger = nil

	if opt.RootUrl == "" {
		opt.RootUrl = mavenRepoURL
	}

	indexDir := filepath.Join(opt.CacheDir, "indexes")
	log.Printf("Index dir %s", indexDir)

	return Crawler{
		dir:     indexDir,
		http:    client,
		rootUrl: opt.RootUrl,
		urlCh:   make(chan string, opt.Limit*10),
		limit:   semaphore.NewWeighted(opt.Limit),
	}
}

func (c *Crawler) Crawl(ctx context.Context) error {
	log.Println("Crawl maven repository and save indexes")
	errCh := make(chan error)
	defer close(errCh)

	// Add a root url
	c.urlCh <- c.rootUrl
	c.wg.Add(1)

	go func() {
		c.wg.Wait()
		close(c.urlCh)
	}()

	crawlDone := make(chan struct{})

	// For the HTTP loop
	go func() {
		defer func() { crawlDone <- struct{}{} }()

		var count int
		for url := range c.urlCh {
			count++
			if count%1000 == 0 {
				log.Printf("Count: %d", count)
			}
			if err := c.limit.Acquire(ctx, 1); err != nil {
				errCh <- xerrors.Errorf("semaphore acquire error: %w", err)
				return
			}
			go func(url string) {
				defer c.limit.Release(1)
				defer c.wg.Done()
				if err := c.Visit(url); err != nil {
					errCh <- xerrors.Errorf("visit error: %w", err)
				}
			}(url)
		}
	}()

loop:
	for {
		select {
		// Wait for DB update to complete
		case <-crawlDone:
			break loop
		case err := <-errCh:
			close(c.urlCh)
			return err

		}
	}
	log.Println("Crawl completed")
	return nil
}

func (c *Crawler) Visit(url string) error {
	resp, err := c.http.Get(url)
	if err != nil {
		return xerrors.Errorf("http get error (%s): %w", url, err)
	}
	defer resp.Body.Close()

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	var children []string
	var foundMetadata bool
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := selection.Text()
		if link == "maven-metadata.xml" {
			foundMetadata = true
			return
		} else if link == "../" || !strings.HasSuffix(link, "/") {
			// only `../` and dirs have `/` suffix. We don't need to check other files.
			return
		}

		children = append(children, link)
	})

	if foundMetadata {
		meta, err := c.parseMetadata(url + "maven-metadata.xml")
		if err != nil {
			return xerrors.Errorf("metadata parse error: %w", err)
		}
		if meta != nil {
			if err = c.crawlLatestJar(url, meta); err != nil {
				return err
			}
			// Return here since there is no need to crawl dirs anymore.
			return nil
		}
	}

	c.wg.Add(len(children))

	go func() {
		for _, child := range children {
			c.urlCh <- url + child
		}
	}()

	return nil
}

func checkFileExists(filePath string) bool {
	_, error := os.Stat(filePath)
	return !errors.Is(error, os.ErrNotExist)
}

func (c *Crawler) crawlLatestJar(baseURL string, meta *Metadata) error {
	fileName := fmt.Sprintf("%s.json", meta.ArtifactID)
	filePath := filepath.Join(c.dir, "metadata", meta.GroupID, fileName)

	if checkFileExists(filePath) {
		return nil
	}

	latestVersion := meta.Versioning.Latest

	if latestVersion == "" {
		numVersions := len(meta.Versioning.Versions)
		if numVersions == 0 {
			log.Printf("Unable to find any versions for %s\n", baseURL)
			return nil
		}
		latestVersion = meta.Versioning.Versions[numVersions-1]
	}

	jarFileName := fmt.Sprintf("/%s-%s.jar", meta.ArtifactID, latestVersion)
	url := baseURL + latestVersion + jarFileName
	jarFilePath := filepath.Join(c.dir, "jars", meta.GroupID, jarFileName)
	success, err := c.downloadJar(url, jarFilePath)
	if err != nil {
		return err
	}

	if !success {
		return nil
	}

	index := &Index{
		URL:          url,
		LocalPath:    jarFilePath,
		GroupID:      meta.GroupID,
		ArtifactID:   meta.ArtifactID,
		Version:      latestVersion,
		ArchiveType:  types.JarType,
		ExpectedPURL: fmt.Sprintf("pkg:maven/%s/%s@%s", meta.GroupID, meta.ArtifactID, latestVersion),
	}

	if err := fileutil.WriteJSON(filePath, index); err != nil {
		return xerrors.Errorf("json write error: %w", err)
	}

	return nil
}

func (c *Crawler) parseMetadata(url string) (*Metadata, error) {
	resp, err := c.http.Get(url)
	if err != nil {
		return nil, xerrors.Errorf("can't get url: %w", err)
	}
	defer resp.Body.Close()

	var meta Metadata
	if err = xml.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, xerrors.Errorf("%s decode error: %w", url, err)
	}
	// we don't need metadata.xml files from version folder
	// e.g. https://repo.maven.apache.org/maven2/HTTPClient/HTTPClient/0.3-3/maven-metadata.xml
	if len(meta.Versioning.Versions) == 0 {
		return nil, nil
	}
	// also we need to skip metadata.xml files from groupID folder
	// e.g. https://repo.maven.apache.org/maven2/args4j/maven-metadata.xml
	if len(strings.Split(url, "/")) < 7 {
		return nil, nil
	}
	return &meta, nil
}

func (c *Crawler) downloadJar(url string, jarFilePath string) (bool, error) {
	resp, err := c.http.Get(url)
	// some projects don't have xxx.jar and xxx.jar.sha1 files
	if resp.StatusCode == http.StatusNotFound {
		log.Printf("jar not found for %s\n", url)
		return false, nil // TODO add special error for this
	}
	if err != nil {
		return false, xerrors.Errorf("can't get jar from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if err := os.MkdirAll(filepath.Dir(jarFilePath), os.ModePerm); err != nil {
		return false, xerrors.Errorf("unable to create a directory: %w", err)
	}

	f, err := os.Create(jarFilePath)
	if err != nil {
		return false, xerrors.Errorf("unable to open %s: %w", jarFilePath, err)
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return false, err
	}

	return true, nil
}

/* func (c *Crawler) correctIdFromJar(url string, jarName string, groupId string, artifactId string, keep bool) (bool, string, error) {
	//fmt.Print(jarName)
	filePath := filepath.Join(c.dir, "jars", groupId, jarName)
	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return false, "", xerrors.Errorf("unable to create a directory: %w", err)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return false, "", xerrors.Errorf("unable to open %s: %w", filePath, err)
	}
	defer f.Close()

	if !keep {
		defer os.Remove(filePath)
	}

	resp, err := c.http.Get(url)
	// some projects don't have xxx.jar and xxx.jar.sha1 files
	if resp.StatusCode == http.StatusNotFound {
		return false, "", nil // TODO add special error for this
	}
	if err != nil {
		return false, "", xerrors.Errorf("can't get jar from %s: %w", url, err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return false, "", err
	}

	detection, err := source.Detect(filePath, source.DefaultDetectConfig())
	if err != nil {
		return false, "", fmt.Errorf("package cataloger: %w", err)
	}

	src, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	if err != nil {
		return false, "", fmt.Errorf("package cataloger: %w", err)
	}

	catalog, _, _, err := syft.CatalogPackages(src, cataloger.DefaultConfig())
	if err != nil {
		return false, "", fmt.Errorf("package cataloger: %w", err)
	}

	if catalog != nil {
		packages := catalog.PackagesByName(artifactId)
		if len(packages) > 0 {
			p := packages[0]

			if strings.HasPrefix(p.PURL, fmt.Sprintf("pkg:maven/%s/%s", groupId, artifactId)) {
				return true, p.PURL, nil
			}

			fmt.Printf("%s:%s syft purl: %s\n", groupId, artifactId, p.PURL)
			return false, p.PURL, nil
		}
	}

	return false, "", nil
} */
