package envenc

// This is the old version of the CLI (v1)

// import (
// 	"errors"
// 	"fmt"
// 	"path/filepath"
// 	"sort"
// 	"strings"
// 	"syscall"

// 	// "github.com/gouniverse/utils"
// 	"github.com/mingrammer/cfmt"
// 	"github.com/samber/lo"
// 	"golang.org/x/term"
// )

// func Cli(args []string) {
// 	commands := map[string]func([]string){
// 		"init":        cliVaultInit,
// 		"encrypt":     cliEncrypt,
// 		"decrypt":     cliDecrypt,
// 		"obfuscate":   cliObfuscate,
// 		"deobfuscate": cliDeobfuscate,
// 		"key-set":     cliVaultKeySet,
// 		"key-list":    cliVaultKeyList,
// 		"key-remove":  cliVaultKeyRemove,
// 	}

// 	if len(args) < 2 {
// 		cliShowHelp([]string{})
// 		return
// 	}

// 	command := lo.ValueOr(commands, args[1], cliShowHelp)

// 	command(args[2:])
// }

// func cliEncrypt(_ []string) {
// 	input, err := cliAskString("Enter string to encode:")

// 	if err != nil {
// 		cfmt.Errorln("There was an error:")
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	password, err := cliAskPassword()

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	enc, err := Encrypt(input, password)

// 	if err != nil {
// 		cfmt.Errorln("There was an error:")
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	cfmt.Infoln("The encrypted string is:")
// 	cfmt.Successln(enc)
// }

// func cliDecrypt(_ []string) {
// 	input, err := cliAskString("Enter string to decode:")

// 	if err != nil {
// 		cfmt.Errorln("There was an error:")
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	password, err := cliAskPassword()

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	dec, err := Decrypt(input, password)

// 	if err != nil {
// 		cfmt.Errorln("There was an error:")
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	cfmt.Infoln("The decrypted string is:")
// 	cfmt.Successln(dec)
// }

// func cliObfuscate(_ []string) {
// 	input, err := cliAskString("Enter string to obfuscate:")

// 	if err != nil {
// 		cfmt.Errorln("There was an error:")
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	obf, err := Obfuscate(input)

// 	if err != nil {
// 		cfmt.Errorln("There was an error:")
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	deObf, err := Deobfuscate(obf)

// 	if err != nil {
// 		cfmt.Errorln("There was an error:")
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	if input != deObf {
// 		cfmt.Errorln("Sorry, this string is not supported.")
// 		return
// 	}

// 	cfmt.Infoln("The obfuscated string is:")
// 	cfmt.Successln(obf)
// }

// func cliDeobfuscate(_ []string) {
// 	input, err := cliAskString("Enter string to deobfuscate:")

// 	if err != nil {
// 		cfmt.Errorln("There was an error:")
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	deObf, err := Deobfuscate(input)

// 	if err != nil {
// 		cfmt.Errorln("There was an error:")
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	cfmt.Infoln("The deobfuscated string is:")
// 	cfmt.Successln(deObf)
// }

// func cliVaultInit(args []string) {
// 	vaultPath, err := cliVaultPathFromArgs(args)

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	vaultPassword, err := cliAskPassword()

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	cfmt.Infoln("Confirm password to continue...")
// 	cfmt.Infoln("")

// 	vaultPasswordConfirm, err := cliAskPassword()

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	if vaultPassword != vaultPasswordConfirm {
// 		cfmt.Errorln("passwords do not match!")
// 		return
// 	}

// 	err = Init(vaultPath, vaultPassword)

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	cfmt.Successln("Vault initialized successfully at " + vaultPath)
// }

// func cliVaultKeyList(args []string) {
// 	vaultPath, err := cliVaultPathFromArgs(args)

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	vaultPassword, err := cliAskPassword()

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	data, err := KeyListFromFile(vaultPath, vaultPassword)

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	if len(data) == 0 {
// 		cfmt.Successln("Key list is empty!")
// 		cfmt.Successln("")
// 		return
// 	}

// 	cfmt.Successln("Total keys: ", len(data))
// 	cfmt.Successln("")

// 	keys := lo.Keys(data)

// 	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

// 	lo.ForEach(keys, func(key string, _ int) {
// 		cfmt.Successln(key, " = ", data[key])
// 	})

// 	cfmt.Successln("")
// }

// func cliVaultKeyRemove(args []string) {
// 	vaultPath, err := cliVaultPathFromArgs(args)

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	vaultPassword, err := cliAskPassword()

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	key, err := cliAskKey()

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	err = KeyRemove(vaultPath, vaultPassword, key)

// 	if err != nil {
// 		cfmt.Errorln(err)
// 	}

// 	cfmt.Successln("Removed key successfully!")
// 	cfmt.Successln("")
// }

// func cliVaultKeySet(args []string) {
// 	vaultPath, err := cliVaultPathFromArgs(args)

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	password, err := cliAskPassword()

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	key, err := cliAskKey()

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	value, err := cliAskValue()

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	err = KeySet(vaultPath, password, key, value)

// 	if err != nil {
// 		cfmt.Errorln(err)
// 		return
// 	}

// 	cfmt.Successln("key set successfully!")
// 	cfmt.Successln("")
// }

// func cliVaultPathFromArgs(args []string) (string, error) {
// 	if len(args) < 1 {
// 		return "", errors.New("- No file path for the vault provided, i.e. env.vault")
// 	}

// 	filePath := args[0]

// 	extension := filepath.Ext(filePath)

// 	if extension != ".vault" {
// 		return "", errors.New("- File extension must be .vault")
// 	}

// 	return filePath, nil
// }

// func cliShowHelp(_ []string) {
// 	cfmt.Infoln("Usage:")
// 	cfmt.Infoln(" - init [vaultPath] - Initialize the vault")
// 	cfmt.Infoln(" - key-list [vaultPath] - Lists all the keys in the vault")
// 	cfmt.Infoln(" - key-remove [vaultPath] - Removes a key from the vault")
// 	cfmt.Infoln(" - key-set [vaultPath] - Sets a key in the vault")
// 	cfmt.Infoln(" - encrypt - Utility function to encrypt a string")
// 	cfmt.Infoln(" - decrypt - Utility function to decrypt a string")
// 	cfmt.Infoln(" - obfuscate - Utility function to obfuscate a string")
// 	cfmt.Infoln(" - deobfuscate - Utility function to deobfuscate a string")
// 	cfmt.Infoln(" - help - Show this help")
// 	cfmt.Infoln("")
// 	cfmt.Infoln("envenc is a tool for managing encrypted environment variables")
// 	cfmt.Infoln("it allows you to store and retrieve environment variables in")
// 	cfmt.Infoln("a secure password protected vault file")
// 	cfmt.Infoln("")
// 	cfmt.Infoln("Example:")
// 	cfmt.Infoln("$> envenc init .env.vault")
// 	cfmt.Infoln("$> envenc key-set .env.vault")
// 	cfmt.Infoln("$> envenc key-list .env.vault")
// 	cfmt.Infoln("$> envenc key-remove .env.vault")
// 	cfmt.Infoln("$> envenc encrypt")
// 	cfmt.Infoln("$> envenc decrypt")
// 	cfmt.Infoln("$> envenc obfuscate")
// 	cfmt.Infoln("$> envenc deobfuscate")
// 	cfmt.Infoln("")
// 	cfmt.Infoln("For more information visit:")
// 	cfmt.Infoln("")
// 	cfmt.Infoln("https://github.com/dracory/envenc")
// }

// func cliAskPassword() (string, error) {
// 	cfmt.Infoln("=================== START: Vault Security ===================")
// 	cfmt.Infoln("Enter vault password:")

// 	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))

// 	if err != nil {
// 		return "", err
// 	}
// 	password := string(passwordBytes)
// 	password = strings.TrimSpace(password)

// 	if password == "" {
// 		return "", errors.New("password cannot be empty")
// 	}

// 	if len(password) < 10 {
// 		return "", errors.New("password must be at least 10 characters long")
// 	}

// 	if len(password) < 10 {
// 		return "", errors.New("password must be at least 10 characters long")
// 	}

// 	cfmt.Infoln("Password: ", strPadLeft("***", 32, "*"))
// 	cfmt.Infoln("==================== END: Vault Security ====================")
// 	cfmt.Infoln("")
// 	fmt.Print("\n")

// 	return password, nil
// }

// func cliAskKey() (string, error) {
// 	cfmt.Infoln("Enter key name:")

// 	key := ""
// 	fmt.Scanln(&key)
// 	key = strings.TrimSpace(key)

// 	if key == "" {
// 		return "", errors.New("key name cannot be empty")
// 	}

// 	if strings.ToUpper(key) != key {
// 		return "", errors.New("key name must be uppercase")
// 	}

// 	return key, nil
// }

// func cliAskValue() (string, error) {
// 	cfmt.Infoln("Enter value:")

// 	value := ""

// 	fmt.Scanln(&value)

// 	if value == "" {
// 		return "", errors.New("value cannot be empty")
// 	}

// 	return value, nil
// }

// func cliAskString(prompt string) (string, error) {
// 	cfmt.Infoln(prompt)

// 	key := ""
// 	fmt.Scanln(&key)
// 	key = strings.TrimSpace(key)

// 	if key == "" {
// 		return "", errors.New("string cannot be empty")
// 	}

// 	return key, nil
// }
