package manifest

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"mdkr/structs"
	"os"
	"path"
	"strings"
)

func FManifest(Imgpth string, img string, imgstruct *structs.Img) error {
	fdo, err := os.Open(Imgpth)
	if err != nil {
		return err
	}
	defer fdo.Close()

	tr := tar.NewReader(fdo)

	var manifestenc []byte

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if hdr.Name == "manifest.json" {
			manifestenc, err = io.ReadAll(tr)
			if err != nil {
				return err
			}
			break
		}
	}

	if len(manifestenc) == 0 {
		return fmt.Errorf("manifest.json empty")
	}

	var manindex []structs.Manifest
	err = json.Unmarshal(manifestenc, &manindex)
	if err != nil {
		return fmt.Errorf("error unmarshalling manifest.json: %w", err)
	}

	idx := -1

	if img == "" {
		if len(manindex) != 1 {
			return fmt.Errorf("manifest contains multiple images, cannot guess the tag")
		}
		idx = 0
		fmt.Printf("single entry, defaulting its tag")
	} else {
		for i, m := range manindex {
			for _, tag := range m.RepoTags {
				if tag == img {
					idx = i
					break
				}
			}
			if idx >= 0 {
				break
			}
		}
	}

	if idx < 0 {
		return fmt.Errorf("tag %s not found in manifest", img)
	}

	fidx := manindex[idx]
	layerpths := make(map[string]int, len(fidx.Layers))

	for i, ilayerpth := range fidx.Layers {
		layerpths[Pathcln(ilayerpth)] = i
	}

	layertmp := make([]string, len(fidx.Layers))

	if _, err := fdo.Seek(0, io.SeekStart); err != nil {
		return err
	}

	var conf = Pathcln(fidx.Config)
	var confbuf []byte

	tr = tar.NewReader(fdo)

	for {

		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		hdrnm := Pathcln(hdr.Name)
		if hdrnm == conf {
			confbuf, err = io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("error reading config %s: %w", conf, err)
			}
			continue
		}
		if i, ok := layerpths[hdrnm]; ok {
			tmp, err := os.CreateTemp("", "imglayer_*")
			if err != nil {
				return fmt.Errorf("error creating temp file for layer %s: %w", hdrnm, err)
			}
			if _, err := io.Copy(tmp, tr); err != nil {
				tmp.Close()
				os.Remove(tmp.Name())
				return fmt.Errorf("error copying layer %s to temp file: %w", hdrnm, err)
			}
			if err := tmp.Close(); err != nil {
				return err
			}
			layertmp[i] = tmp.Name()
			delete(layerpths, hdrnm)
			if len(layerpths) == 0 && confbuf != nil {
				break
			}
			continue
		}
	}
	if len(layerpths) != 0 {
		for missingLayer := range layerpths {
			return fmt.Errorf("layer %s not found in image tarball", missingLayer)
		}
	}
	if confbuf == nil {
		confbuf = []byte("{}")
	}

	imgstruct.Indx = fidx
	imgstruct.Layerpth = layertmp
	imgstruct.Imgpth = Imgpth
	imgstruct.Confjs = confbuf

	return nil
}

func Pathcln(pth string) string {
	pth = path.Clean(pth)
	pth = strings.ReplaceAll(pth, "\\", "/")

	for strings.HasPrefix(pth, "/") {
		pth = strings.TrimPrefix(pth, "/")
	}

	for strings.HasPrefix(pth, "../") {
		pth = strings.TrimPrefix(pth, "../")
	}

	for strings.HasPrefix(pth, "./") {
		pth = strings.TrimPrefix(pth, "./")
	}

	pth = strings.TrimSuffix(pth, "/")

	return pth
}
