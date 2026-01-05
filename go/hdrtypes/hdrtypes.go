package hdrtypes

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mdkr/manifest"
	"mdkr/structs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func Tardir(basepth string, hdr *tar.Header, meta map[string]structs.Metadata) error {
	dirpath := manifest.Pathcln(hdr.Name)
	targetpth := filepath.Join(basepth, dirpath)
	if err := os.MkdirAll(targetpth, 0o755); err != nil {
		return fmt.Errorf("error creating directory %s: %v", targetpth, err)
	}

	info := hdr.FileInfo().Mode()
	meta[targetpth] = structs.Metadata{
		Mode:  info,
		Uid:   hdr.Uid,
		Gid:   hdr.Gid,
		Mtime: hdr.ModTime,
	}
	return nil
}

func Tarfile(basepth string, hdr *tar.Header, tr *tar.Reader) error {
	fpth := manifest.Pathcln(hdr.Name)
	targetpth := filepath.Join(basepth, fpth)
	dirv := filepath.Dir(targetpth)
	if err := os.MkdirAll(dirv, 0o755); err != nil {
		return fmt.Errorf("error creating directory %s: %v", dirv, err)
	}

	if _, err := os.Lstat(targetpth); err == nil {
		if err := os.RemoveAll(targetpth); err != nil {
			return fmt.Errorf("error removing existing file %s: %v", targetpth, err)
		}
	}

	f, err := os.OpenFile(targetpth, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("error creating file %s: %v", targetpth, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, tr); err != nil {
		return fmt.Errorf("error writing file %s: %v", targetpth, err)
	}

	mode := hdr.FileInfo().Mode()

	if err := os.Chmod(targetpth, mode.Perm()); err != nil {
		fmt.Printf("cannot set permissions on file %s: %v", targetpth, err)
	}

	if err := os.Chown(targetpth, hdr.Uid, hdr.Gid); err != nil {
		fmt.Printf("unable to change ownership of file %s: %v\n", targetpth, err)
	}

	if err := os.Chtimes(targetpth, hdr.AccessTime, hdr.ModTime); err != nil {
		fmt.Printf("cannot set times on file %s: %v", targetpth, err)
	}

	return nil
}

func Tarsym(basepth string, hdr *tar.Header) error {
	sympath := manifest.Pathcln(hdr.Name)
	targetpth := filepath.Join(basepth, sympath)
	linkname := hdr.Linkname
	dirv := filepath.Dir(targetpth)
	if err := os.MkdirAll(dirv, 0o755); err != nil {
		return fmt.Errorf("error creating directory %s: %v", dirv, err)
	}

	if _, err := os.Lstat(targetpth); err == nil {
		if err := os.RemoveAll(targetpth); err != nil {
			return fmt.Errorf("error removing existing file %s: %v", targetpth, err)
		}
	}

	if err := os.Symlink(linkname, targetpth); err != nil {
		return fmt.Errorf("error creating symlink %s -> %s: %v", targetpth, linkname, err)
	}

	return nil
}

func Tarhard(basepth string, hdr *tar.Header, linkq map[string][]string) error {
	hardlnkpth := manifest.Pathcln(hdr.Name)
	targetpth := filepath.Join(basepth, hardlnkpth)
	linkname := manifest.Pathcln(hdr.Linkname)
	linkpth := filepath.Join(basepth, linkname)
	dirv := filepath.Dir(targetpth)
	if err := os.MkdirAll(dirv, 0o755); err != nil {
		return fmt.Errorf("error creating directory %s: %v", dirv, err)
	}
	if _, err := os.Lstat(linkpth); err == nil {
		_ = os.RemoveAll(targetpth)
		if err := os.Link(linkpth, targetpth); err != nil {
			return fmt.Errorf("error creating hard link %s -> %s: %v", targetpth, linkpth, err)
		}
		return nil
	}

	linkq[linkname] = append(linkq[linkname], hardlnkpth)
	return nil
}

func Tarx(meta *structs.Paxmeta, hdr *tar.Header, tr io.Reader) error {
	if hdr.Size <= 0 {
		return nil
	}

	buf := make([]byte, int(hdr.Size))
	if _, err := io.ReadFull(tr, buf); err != nil {
		return fmt.Errorf("error reading pax extended header data for %s: %v", hdr.Name, err)
	}

	lines := bytes.Split(buf, []byte{'\n'})
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		space := bytes.IndexByte(line, ' ')
		if space == -1 {
			continue
		}

		rec := line[space+1:]
		eq := bytes.IndexByte(rec, '=')
		if eq == -1 {
			continue
		}
		key := string(rec[:eq])
		val := string(rec[eq+1:])

		switch key {
		case "path":
			meta.Path = val
		case "linkpath":
			meta.Linkpath = val
		case "uid":
			if uid, err := strconv.Atoi(val); err == nil {
				meta.Uid, meta.UidS = uid, true
			}
		case "gid":
			if gid, err := strconv.Atoi(val); err == nil {
				meta.Gid, meta.GidS = gid, true
			}
		case "mtime":
			if mtime, err := strconv.ParseFloat(val, 64); err == nil {
				sec := int64(mtime)
				nsec := int64((mtime - float64(sec)) * 1e9)
				meta.Mtime, meta.MtimeS = time.Unix(sec, nsec), true
			}
		}
	}
	return nil

}

func Tarpax(meta *structs.Paxmeta, hdr *tar.Header) {
	if meta.Ln != "" {
		hdr.Name = meta.Ln
	}
	if meta.Ll != "" {
		hdr.Linkname = meta.Ll
	}
	if meta.Path != "" {
		hdr.Name = meta.Path
	}
	if meta.Linkpath != "" {
		hdr.Linkname = meta.Linkpath
	}
	if meta.UidS {
		hdr.Uid = meta.Uid
	}
	if meta.GidS {
		hdr.Gid = meta.Gid
	}
	if meta.MtimeS {
		hdr.ModTime = meta.Mtime
	}
	*meta = structs.Paxmeta{}
}

func Tarln(meta *structs.Paxmeta, hdr *tar.Header, tr io.Reader) error {
	if hdr.Size <= 0 {
		return nil
	}

	buf := make([]byte, int(hdr.Size))
	if _, err := io.ReadFull(tr, buf); err != nil {
		return fmt.Errorf("error reading LongName data for %s: %v", hdr.Name, err)
	}

	nm := strings.TrimRight(string(buf), "\x00\n")
	meta.Ln = nm
	return nil

}

func Tarll(meta *structs.Paxmeta, hdr *tar.Header, tr io.Reader) error {
	if hdr.Size <= 0 {
		return nil
	}

	buf := make([]byte, int(hdr.Size))
	if _, err := io.ReadFull(tr, buf); err != nil {
		return fmt.Errorf("error reading LongLink data for %s: %v", hdr.Name, err)
	}

	nm := strings.TrimRight(string(buf), "\x00\n")
	meta.Ll = nm
	return nil

}

func Hlresolve(basepth string, linkq map[string][]string) error {
	for lnknm, pths := range linkq {
		trgt := filepath.Join(basepth, lnknm)
		for _, hlpth := range pths {
			dst := filepath.Join(basepth, hlpth)
			if err := os.Link(trgt, dst); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("error creating hard link %s -> %s: %v", dst, trgt, err)
			}
		}
	}
	return nil
}
