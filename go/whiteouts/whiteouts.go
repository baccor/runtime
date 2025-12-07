package whiteouts

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"mdkr/hdrtypes"
	"mdkr/manifest"
	"mdkr/structs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func Whiteouts(tr *tar.Reader, meta map[string]structs.Metadata, basepth string) error {
	linkq := make(map[string][]string)
	var paxm structs.Paxmeta
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		hdrname := manifest.Pathcln(hdr.Name)
		hdrtype := hdr.Typeflag
		base := path.Base(hdrname)
		dir := filepath.Dir(hdrname)

		switch {
		case base == ".wh..wh..opq":
			if err := opq(filepath.Join(basepth, manifest.Pathcln(dir))); err != nil {
				return err
			}

		case strings.HasPrefix(base, ".wh."):
			delname := strings.TrimPrefix(base, ".wh.")
			target := manifest.Pathcln(path.Join(manifest.Pathcln(dir), delname))
			if err := whdel(target, basepth); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("error deleting whiteout %v", err)
			}

		case hdrtype == tar.TypeDir:
			hdrtypes.Tarpax(&paxm, hdr)
			if err := hdrtypes.Tardir(basepth, hdr, meta); err != nil {
				return err
			}

		case hdrtype == tar.TypeReg:
			hdrtypes.Tarpax(&paxm, hdr)
			if err := hdrtypes.Tarfile(basepth, hdr, tr); err != nil {
				return err
			}

		case hdrtype == tar.TypeSymlink:
			hdrtypes.Tarpax(&paxm, hdr)
			if err := hdrtypes.Tarsym(basepth, hdr); err != nil {
				return err
			}

		case hdrtype == tar.TypeLink:
			hdrtypes.Tarpax(&paxm, hdr)
			if err := hdrtypes.Tarhard(basepth, hdr, linkq); err != nil {
				return err
			}

		case hdrtype == tar.TypeXHeader:
			if err := hdrtypes.Tarx(&paxm, hdr, tr); err != nil {
				return err
			}

		case hdrtype == tar.TypeGNULongName:
			if err := hdrtypes.Tarln(&paxm, hdr, tr); err != nil {
				return err
			}

		case hdrtype == tar.TypeGNULongLink:
			if err := hdrtypes.Tarll(&paxm, hdr, tr); err != nil {
				return err
			}

		default:
			fmt.Printf("Unknown tar header type: %v in %s\n", hdrtype, hdrname)

		}

	}

	if err := hdrtypes.Hlresolve(basepth, linkq); err != nil {
		return err
	}

	return nil

}
func opq(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, file := range files {
		err := os.RemoveAll(filepath.Join(dir, file.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

func whdel(target, basepth string) error {

	switch {
	case filepath.IsAbs(target):
		target = filepath.Clean(target)
		trgt, err := filepath.Rel(basepth, target)
		if err != nil {
			return err
		}
		if trgt == ".." || strings.HasPrefix(trgt, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("whiteout target escaped base path: %s", target)
		} else {
			return whdelhlp(trgt, basepth)
		}

	case !filepath.IsAbs(target):
		trgt := manifest.Pathcln(target)
		if trgt == "" {
			return nil
		}
		return whdelhlp(trgt, basepth)
	}
	return nil
}

func whdelhlp(trgt, basepth string) error {

	fpth := filepath.Join(basepth, trgt)

	crnt := basepth
	parts := strings.Split(trgt, string(os.PathSeparator))
	for i, p := range parts {
		crnt = filepath.Join(crnt, p)
		file, err := os.Lstat(crnt)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		if i < len(parts)-1 && file.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("encountered symlink in path: %s", crnt)
		}

	}
	return os.RemoveAll(fpth)
}
