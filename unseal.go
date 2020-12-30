package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var help bool
var cmd string
var group string
var execargs []string

var secretsFile string

const mode = 0600

func init() {
	flag.BoolVar(&help, "help", false, "Show this usage message")
	flag.StringVar(&cmd, "cmd", "wrap", "Command to run\nValid commands:\n\tdecrypt\n\tedit\n\twrap\n")
	flag.StringVar(&group, "group", "", "Secrets group to execute on")
	flag.Parse()

	execargs = flag.Args()
	secretsFile = fmt.Sprintf("%s/.secrets/%s.gpg", os.Getenv("HOME"), group)
}

func system(command string, pipe bool, args ...string) (string, string, error) {
	var err error
	var stdout, stderr []byte
	var stdoutPipe, stderrPipe io.ReadCloser

	c := exec.Command(command, args...)

	c.Stdin = os.Stdin
	if pipe {
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
	} else {
		stdoutPipe, err = c.StdoutPipe()
		if err != nil {
			return "", "", err
		}
		defer stdoutPipe.Close()

		stderrPipe, err = c.StderrPipe()
		if err != nil {
			return "", "", err
		}
		defer stderrPipe.Close()
	}

	err = c.Start()
	if err != nil {
		return "", "", err
	}

	if !pipe {
		stdout, err = ioutil.ReadAll(stdoutPipe)
		if err != nil {
			return "", "", err
		}

		stderr, err = ioutil.ReadAll(stderrPipe)
		if err != nil {
			return "", "", err
		}

	}

	err = c.Wait()

	return string(stdout), string(stderr), err
}

func gpg(args ...string) (string, string, error) {
	return system("gpg", false, append([]string{"--quiet", "--no-verbose"}, args...)...)
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	if err != nil {
		return false
	}

	return true
}

func main() {
	if help {
		printHelp()
		return
	}

	switch cmd {
	case "decrypt":
		fmt.Println(decrypt())
	case "edit":
		edit()
	case "wrap":
		wrap()
	default:
		fmt.Println("Unknown command: ", cmd)
		printHelp()
	}
}

func ensureSecrets() {
	ensureGroup()

	if !fileExists(secretsFile) {
		fmt.Println("Secrets file ", group, "does not exist. Create one with the edit command")
		os.Exit(1)
	}
}

func ensureGroup() {
	if group == "" {
		fmt.Println("Group name is required")
		os.Exit(1)
	}
}

func decryptFile() string {
	if !fileExists(secretsFile) {
		return ""
	}

	stdout, stderr, err := gpg("-d", secretsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err, "\n", stderr)
		os.Exit(1)
	}

	return strings.TrimSpace(stdout)
}

func decrypt() string {
	ensureSecrets()

	return decryptFile()
}

func edit() {
	var contents string
	ensureGroup()

	if fileExists(secretsFile) {
		contents = decryptFile()
	}

	file, err := writeTmpFile(contents)
	if err != nil {
		fmt.Println("Error opening temporary file")
		os.Exit(1)
	}
	cleanup := func() {
		file.Close()
		err := os.Remove(file.Name())
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error cleaning up temp file. Unencrypted secrets may have leaked ", err)
		}
	}

	tmpEnc := fmt.Sprintf("%s.gpg", file.Name())

	err = editFile(file.Name())
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error editing secrets file: ", err)
		os.Exit(1)
	}

	_, stderr, err := gpg("--armor", "--cipher-algo", "AES256", "-c", "-o", tmpEnc, file.Name())
	cleanup()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error encrypting temporary file: ", err, "\n", stderr)
		os.Exit(1)
	}

	err = copyFile(tmpEnc, secretsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to move encrypted temp file to secrets dir: ", err)
		cleanup()
		os.Exit(1)
	}
}

func wrap() {
	if len(execargs) < 1 {
		fmt.Fprintln(os.Stderr, "Wrap requires at least an external program to run")
		os.Exit(1)
	}

	ensureSecrets()

	insertEnvironment(parseEnvironment(decrypt()))

	_, _, err := system(execargs[0], true, execargs[1:len(execargs)]...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error executing external command: ", err)
	}
}

func writeTmpFile(contents string) (*os.File, error) {
	tmpFile := filepath.Join(os.TempDir(), "unseal."+randChars())

	f, err := os.Create(tmpFile)
	if err != nil {
		return nil, err
	}

	err = f.Chmod(mode)
	if err != nil {
		f.Close()
		return nil, err
	}

	_, err = f.WriteString(contents)
	if err != nil {
		f.Close()
		return nil, err
	}

	return f, err
}

func editFile(file string) error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}

	_, _, err := system(editor, true, file)
	return err
}

func copyFile(oldpath, newpath string) error {
	err := os.Rename(oldpath, newpath)
	if err != nil {
		byteArr, err2 := ioutil.ReadFile(oldpath)
		if err2 != nil {
			return err2
		}

		err2 = ioutil.WriteFile(newpath, byteArr, mode)
		if err2 == nil {
			_ = os.Remove(oldpath)
		} else {
			_ = os.Remove(newpath)
		}

		return err2
	}
	return err
}

func insertEnvironment(vars map[string]string) {
	for key, val := range vars {
		os.Setenv(key, val)
	}
}

func parseEnvironment(raw string) map[string]string {
	vars := make(map[string]string)

	for _, v := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if v == strings.TrimSpace("") {
			continue
		}

		splitVar := strings.SplitN(v, "=", 2)
		if len(splitVar) > 1 {
			vars[splitVar[0]] = splitVar[1]
		}
	}

	return vars
}

func randChars() string {
	buf := make([]byte, 4)
	_, err := rand.Read(buf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to create temporary file")
		os.Exit(1)
	}

	return hex.EncodeToString(buf)
}

func printHelp() {
	flag.PrintDefaults()
}
