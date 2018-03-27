package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/template"

	"github.com/atotto/clipboard"
	"golang.org/x/crypto/ssh/terminal"
)

var path = flag.String("p", "~/.pwsafe/default.psafe3", "path to the database")
var stdin = flag.Bool("S", false, "read password from stdin")

var helpTmpl = template.Must(template.New("help").Parse(`Usage: {{.}} [options] <list|copy|show>

  {{.}} list [<name regexp>]
    list all entries or entries matching given regexp

  {{.}} copy <name regexp>
    copy password to clipboard, after user presses any key, copy username and exit

  {{.}} show <name regexp>
    print all fields for matching entries

Examples:
  $ echo -n bogus12345 | {{.}} -p ./simple.psafe3 -S list
  Test eight
  Test Four
  Test.Test One
  Test seven
  Test Two
  Test.Test Nine
  Test six
  Test.Test One
  Test Five

  $ echo -n bogus12345 | {{.}} -p ./simple.psafe3 -S list \\.Test
  Test.Test One
  Test.Test Nine
  Test.Test One

  $ echo -n bogus12345 | {{.}} -p ./simple.psafe3 -S copy Test six
  Password is now in your clipboard, press ENTER to copy username

Options:
`))

// toClipboard copies item password and username to clipboard.
func toClipboard(i *Item) {
	if err := clipboard.WriteAll(i.Fields[TypePassword].String()); err != nil {
		log.Fatal("Can't paste to cliboard: ", err)
	}
	fmt.Println("Password is now in your clipboard, press ENTER to copy username")
	var garbage string
	fmt.Scanln(&garbage)
	if err := clipboard.WriteAll(i.Fields[TypeUsername].String()); err != nil {
		log.Fatal("Can't paste to cliboard: ", err)
	}
}

// expandHome replaces ~ in the path with the $HOME.
func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("Can't get current user info: ", err)
		}
		return strings.Replace(p, "~", usr.HomeDir, 1)
	}
	return p
}

// unlockKeychain prompts password and returns new unlocked keychain.
func unlockKeychain(stdin bool, path string) *Keychain {
	var pwd string
	if stdin {
		fmt.Scanln(&pwd)
	} else {
		fmt.Print("Password: ")
		t, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Can't read password: ", err)
		}
		pwd = string(t)
	}
	kc, err := NewKeychain(expandHome(path))
	if err != nil {
		log.Fatal("Can't create keychain: ", err)
	}
	if err = kc.Unlock(pwd); err != nil {
		log.Fatal("Can't unlock keychain: ", err)
	}
	return kc
}

func argsToRE(args []string) string {
	return "(?i)" + strings.Join(args[1:], " ")
}

func main() {
	flag.Usage = func() {
		if err := helpTmpl.Execute(flag.CommandLine.Output(), filepath.Base(os.Args[0])); err != nil {
			log.Fatal("Can't execute template: ", err)
		}

		flag.PrintDefaults()
	}

	flag.Parse()
	args := flag.Args()

	cmd := "help"
	if len(args) > 0 {
		cmd = args[0]
	}

	switch cmd {
	case "list":
		kc := unlockKeychain(*stdin, *path)
		re := argsToRE(args)
		for i := range kc.Find(re) {
			fmt.Println(i)
		}
	case "show":
		kc := unlockKeychain(*stdin, *path)
		re := argsToRE(args)
		for i := range kc.Find(re) {
			fmt.Println(i)

			if username := i.Fields[TypeUsername]; username != nil {
				fmt.Println("  Username:", username)
			}
			if password := i.Fields[TypePassword]; password != nil {
				fmt.Println("  Password:", password)
			}
			if notes := i.Fields[TypeNotes]; notes != nil {
				fmt.Println("  Notes:", notes)
			}
		}
	case "copy":
		kc := unlockKeychain(*stdin, *path)
		re := argsToRE(args)
		var a []*Item
		for i := range kc.Find(re) {
			a = append(a, i)
		}

		switch len(a) {
		case 0:
			fmt.Println("Nothing found!")
		case 1:
			toClipboard(a[0])
		default:
			fmt.Printf("Found %d entries, select which to copy:\n", len(a))
			for i, item := range a {
				fmt.Printf("#%d %s\n", i, item)
			}

			fmt.Print("Entry index: ")
			var text string
			fmt.Scanln(&text)
			i, err := strconv.Atoi(text)
			if err != nil {
				log.Fatal("Can't convert index to int: ", err)
			}
			if i >= len(a) {
				log.Fatal("Invalid index offset")
			}
			toClipboard(a[i])
		}
	default:
		flag.Usage()
	}
}
