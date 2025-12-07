package structs

import (
	"io/fs"
	"time"
)

type Metadata struct {
	Mode  fs.FileMode
	Uid   int
	Gid   int
	Mtime time.Time
}

type Paxmeta struct {
	Path     string
	Linkpath string
	UidS     bool
	GidS     bool
	MtimeS   bool
	Uid      int
	Gid      int
	Mtime    time.Time
	Ln       string
	Ll       string
}

type Img struct {
	Indx     Manifest
	Layerpth []string
	Imgpth   string
	Confjs   []byte
}

type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}
type Confjs struct {
	Config struct {
		User       string   `json:"User"`
		Env        []string `json:"Env"`
		WorkingDir string   `json:"WorkingDir"`
		Cmd        []string `json:"Cmd"`
		Entrypoint []string `json:"Entrypoint"`
	} `json:"Config"`
}

type State struct {
	Free []string `json:"free"`
	Used []string `json:"used"`
}
