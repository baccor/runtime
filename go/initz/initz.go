package initz

import (
	"encoding/json"
	"fmt"
	"mdkr/structs"
	"os"
)

const pth = "/var/tmp/minidkr/"
const statejs = "/var/tmp/minidkr/state.json"

func Init(st *structs.State) error {
	f, err := os.Open(statejs)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(pth, 0755); err != nil {
				return fmt.Errorf("error creating state dir: %w", err)
			}

			if err := Fip(st); err != nil {
				return fmt.Errorf("error allocating ip pool: %w", err)
			}

			if err := ss(st); err != nil {
				return fmt.Errorf("error saving state: %w", err)
			}

			return nil
		}
		return fmt.Errorf("error opening state file: %w", err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(st); err != nil {
		return fmt.Errorf("error decoding state: %w", err)
	}

	return nil
}

func Fip(st *structs.State) error {
	var ips []string
	for i := 2; i <= 254; i++ {
		ips = append(ips, fmt.Sprintf("10.0.0.%d", i))
	}

	*st = structs.State{
		Free: ips,
		Used: nil,
	}
	return nil
}

func ss(st *structs.State) error {
	f, err := os.Create(statejs)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(st); err != nil {
		return err
	}
	return nil
}

func Alloc(st *structs.State) (string, error) {

	if len(st.Free) == 0 {
		return "", fmt.Errorf("no free IPs available")
	}

	ip := st.Free[0]
	st.Free = st.Free[1:]
	st.Used = append(st.Used, ip)

	if err := ss(st); err != nil {
		return "", fmt.Errorf("error saving state after ip alloc: %v", err)
	}

	return ip, nil

}

func Fr(ip string, st *structs.State) error {

	idx := -1
	for i, v := range st.Used {
		if v == ip {
			idx = i
			break
		}
	}

	if idx == -1 {
		return fmt.Errorf("error locating ip in used list")
	}

	st.Used = append(st.Used[:idx], st.Used[idx+1:]...)

	st.Free = append(st.Free, ip)

	if err := ss(st); err != nil {
		return fmt.Errorf("error saving state after free: %v", err)
	}

	return nil

}
