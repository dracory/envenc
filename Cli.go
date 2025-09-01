package envenc

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/mingrammer/cfmt"
	"github.com/samber/lo"
	"golang.org/x/term"
)

type Cli struct {
	commands map[string]func([]string)

	errorMessage  string
	vaultPath     string
	vaultPassword string
}

func NewCli() *Cli {
	return &Cli{
		commands: map[string]func([]string){
			"init":        (&Cli{}).VaultInit,
			"encrypt":     (&Cli{}).Encrypt,
			"decrypt":     (&Cli{}).Decrypt,
			"obfuscate":   (&Cli{}).Obfuscate,
			"deobfuscate": (&Cli{}).Deobfuscate,
			"help":        (&Cli{}).Help,
			"key-set":     (&Cli{}).VaultKeySet,
			"key-get":     (&Cli{}).VaultKeyGet,
			"key-list":    (&Cli{}).VaultKeyList,
			"key-remove":  (&Cli{}).VaultKeyRemove,
			"ui":          (&Cli{}).UI,
		},
	}
}

// UI is the web user interface
//
// Example:
// $> envenc ui
// $> envenc ui 123.vault
// $> envenc ui 123.vault --address 127.0.0.1:38080
func (c *Cli) UI(args []string) {
	vaultPathOptional, errorMessage := c.FindVaultPathFromArgs(args)

	if errorMessage != "" {
		cfmt.Errorln(errorMessage)
		return
	}

	if vaultPathOptional != "" {
		if !fileExists(vaultPathOptional) {
			cfmt.Errorln("The vault file does not exist")
			return
		}
	}

	(&ui{vaultPath: vaultPathOptional}).Run(args)
}

// Encrypt encrypts a string
func (c *Cli) Encrypt(args []string) {
	input, err := c.askString("Enter string to encrypt:")

	if err != nil {
		cfmt.Errorln("There was an error:")
		cfmt.Errorln(err)
		return
	}

	password, err := c.askString("Enter password:")

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	enc, err := Encrypt(input, password)

	if err != nil {
		cfmt.Errorln("There was an error:")
		cfmt.Errorln(err)
		return
	}

	cfmt.Infoln("The encrypted string is:")
	cfmt.Successln(enc)
}

// Decrypt decrypts a string
func (c *Cli) Decrypt(args []string) {
	input, err := c.askString("Enter string to decrypt:")

	if err != nil {
		cfmt.Errorln("There was an error:")
		cfmt.Errorln(err)
		return
	}

	password, err := c.askString("Enter password:")

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	dec, err := Decrypt(input, password)

	if err != nil {
		cfmt.Errorln("There was an error:")
		cfmt.Errorln(err)
		return
	}

	cfmt.Infoln("The decrypted string is:")
	cfmt.Successln(dec)
}

func (c *Cli) Obfuscate(args []string) {
	input, err := c.askString("Enter string to obfuscate:")

	if err != nil {
		cfmt.Errorln("There was an error:")
		cfmt.Errorln(err)
		return
	}

	obf, err := Obfuscate(input)

	if err != nil {
		cfmt.Errorln("There was an error:")
		cfmt.Errorln(err)
		return
	}

	deObf, err := Deobfuscate(obf)

	if err != nil {
		cfmt.Errorln("There was an error:")
		cfmt.Errorln(err)
		return
	}

	if input != deObf {
		cfmt.Errorln("Sorry, this string is not supported.")
		return
	}

	cfmt.Infoln("The obfuscated string is:")
	cfmt.Successln(obf)
}

func (c *Cli) Deobfuscate(args []string) {
	input, err := c.askString("Enter string to deobfuscate:")

	if err != nil {
		cfmt.Errorln("There was an error:")
		cfmt.Errorln(err)
		return
	}

	deObf, err := Deobfuscate(input)

	if err != nil {
		cfmt.Errorln("There was an error:")
		cfmt.Errorln(err)
		return
	}

	cfmt.Infoln("The deobfuscated string is:")
	cfmt.Successln(deObf)
}

// VaultKeyList lists the keys in the vault
//
// Buisiness logic:
//   - If the vault file is provided as an argument, use it
//   - If the vault file is not provided, ask for it
//   - Check that the vault file exists
//   - Ask for the password to use for the vault
//   - Open the vault file, to confirm the password is correct
//   - List the keys in the vault
//
// Example:
// $> envenc vault-key-list
// $> envenc vault-key-list 123.vault
func (c *Cli) VaultKeyList(args []string) {
	c.vaultPath, c.errorMessage = c.FindVaultPathFromArgs(args)

	if c.errorMessage != "" {
		cfmt.Errorln(c.errorMessage)
		return
	}

	if c.vaultPath == "" {
		c.vaultPath, c.errorMessage = c.AskVaultPath()

		if c.errorMessage != "" {
			cfmt.Errorln(c.errorMessage)
			return
		}
	}

	c.vaultPassword, c.errorMessage = c.AskVaultPassword()

	if c.errorMessage != "" {
		cfmt.Errorln(c.errorMessage)
		return
	}

	cfmt.Infoln("Listing keys in vault: " + c.vaultPath)
	cfmt.Infoln("")

	data, err := KeyListFromFile(c.vaultPath, c.vaultPassword)

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	if len(data) == 0 {
		cfmt.Successln("Key list is empty!")
		cfmt.Successln("")
		return
	}

	cfmt.Successln("Total keys: ", len(data))
	cfmt.Successln("")

	keys := lo.Keys(data)

	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	lo.ForEach(keys, func(key string, _ int) {
		cfmt.Successln(key, " = ", data[key])
	})

	cfmt.Successln("")
}

// VaultKeyGet gets a key from the vault
//
// Buisiness logic:
//   - If the vault file is provided as an argument, use it
//   - If the vault file is not provided, ask for it
//   - Check that the vault file exists
//   - Ask for the password to use for the vault
//   - Open the vault file, to confirm the password is correct
//   - Ask for the key's name to get
//   - Get the key from the vault
//
// Examples:
// $> envenc key-get
// $> envenc key-get 123.vault
func (c *Cli) VaultKeyGet(args []string) {
	c.vaultPath, c.errorMessage = c.FindVaultPathFromArgs(args)

	if c.errorMessage != "" {
		cfmt.Errorln(c.errorMessage)
		return
	}

	if c.vaultPath == "" {
		c.vaultPath, c.errorMessage = c.AskVaultPath()

		if c.errorMessage != "" {
			cfmt.Errorln(c.errorMessage)
			return
		}
	}

	c.vaultPassword, c.errorMessage = c.AskVaultPassword()

	if c.errorMessage != "" {
		cfmt.Errorln(c.errorMessage)
		return
	}

	keyName, errorMessage := c.AskKeyName()

	if errorMessage != "" {
		cfmt.Errorln(errorMessage)
		return
	}

	_, err := KeyListFromFile(c.vaultPath, c.vaultPassword)

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	keyExists, err := KeyExists(c.vaultPath, c.vaultPassword, keyName)

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	if !keyExists {
		cfmt.Errorln("Key does not exist!")
		return
	}

	keyValue, err := KeyGet(c.vaultPath, c.vaultPassword, keyName)

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	if keyValue == "" {
		cfmt.Successln("Key value is empty!")
		return
	}

	cfmt.Infoln("The value of the key is:")
	cfmt.Successln(keyValue)
}

// VaultKeyRemove removes a key from the vault
//
// Buisiness logic:
//   - If the vault file is provided as an argument, use it
//   - If the vault file is not provided, ask for it
//   - Check that the vault file exists
//   - Ask for the password to use for the vault
//   - Open the vault file, to confirm the password is correct
//   - Ask for the key's name to remove
//   - Remove the key from the vault
//
// Examples:
// $> envenc key-remove
// $> envenc key-remove 123.vault
func (c *Cli) VaultKeyRemove(args []string) {
	c.vaultPath, c.errorMessage = c.FindVaultPathFromArgs(args)

	if c.errorMessage != "" {
		cfmt.Errorln(c.errorMessage)
		return
	}

	if c.vaultPath == "" {
		c.vaultPath, c.errorMessage = c.AskVaultPath()

		if c.errorMessage != "" {
			cfmt.Errorln(c.errorMessage)
			return
		}
	}

	c.vaultPassword, c.errorMessage = c.AskVaultPassword()

	if c.errorMessage != "" {
		cfmt.Errorln(c.errorMessage)
		return
	}

	keyName, errorMessage := c.AskKeyName()

	if errorMessage != "" {
		cfmt.Errorln(errorMessage)
		return
	}

	_, err := KeyListFromFile(c.vaultPath, c.vaultPassword)

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	keyExists, err := KeyExists(c.vaultPath, c.vaultPassword, keyName)

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	if !keyExists {
		cfmt.Errorln("Key does not exist!")
		return
	}

	err = KeyRemove(c.vaultPath, c.vaultPassword, keyName)

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	cfmt.Successln("Key removed!")
}

// VaultKeySet sets a key in the vault
//
// Buisiness logic:
//   - If the vault file is provided as an argument, use it
//   - If the vault file is not provided, ask for it
//   - Check that the vault file exists
//   - Ask for the password to use for the vault
//   - Open the vault file, to confirm the password is correct
//   - Ask for the key's name to set
//   - Ask for the key's value to set (must support multiline)
//   - Set the key in the vault
//   - Close the vault file
//   - Ask the user if he wants to add another key
//   - If the user wants to add another key, repeat the process
//
// Examples:
// $> envenc key-set
// $> envenc key-set 123.vault
func (c *Cli) VaultKeySet(args []string) {
	c.vaultPath, c.errorMessage = c.FindVaultPathFromArgs(args)

	if c.errorMessage != "" {
		cfmt.Errorln(c.errorMessage)
		return
	}

	if c.vaultPath == "" {
		c.vaultPath, c.errorMessage = c.AskVaultPath()

		if c.errorMessage != "" {
			cfmt.Errorln(c.errorMessage)
			return
		}
	}

	c.vaultPassword, c.errorMessage = c.AskVaultPassword()

	if c.errorMessage != "" {
		cfmt.Errorln(c.errorMessage)
		return
	}

	_, err := KeyListFromFile(c.vaultPath, c.vaultPassword)

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	keyName, errorMessageKey := c.AskKeyName()

	if errorMessageKey != "" {
		cfmt.Errorln(errorMessageKey)
		return
	}

	keyValue, errorMessageValue := c.AskKeyValue()

	if errorMessageValue != "" {
		cfmt.Errorln(errorMessageValue)
		return
	}

	err = KeySet(c.vaultPath, c.vaultPassword, keyName, keyValue)

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	cfmt.Successln("key set successfully!")
	cfmt.Successln("")
}

// VaultInit initializes a new vault file
//
// Buisiness logic:
//   - If the vault file is provided as an argument, use it
//   - If the vault file is not provided, ask for it
//   - Check that the vault file does not exist already
//   - Ask for the password to use for the vault
//   - Confirm the password to avoid any spelling mistakes
//   - Create the vault file
//
// Examples:
// $> envenc init
// $> envenc init 123.vault
func (c *Cli) VaultInit(args []string) {
	c.vaultPath, c.errorMessage = c.FindVaultPathFromArgs(args)

	if c.errorMessage != "" {
		cfmt.Errorln(c.errorMessage)
		return
	}

	if c.vaultPath == "" {
		c.vaultPath, c.errorMessage = c.AskVaultPath()

		if c.errorMessage != "" {
			cfmt.Errorln(c.errorMessage)
			return
		}
	}

	c.vaultPassword, c.errorMessage = c.AskVaultPasswordWithConfirm()

	if c.errorMessage != "" {
		cfmt.Errorln(c.errorMessage)
		return
	}

	err := Init(c.vaultPath, c.vaultPassword)

	if err != nil {
		cfmt.Errorln(err)
		return
	}

	cfmt.Successln("Vault initialized successfully at " + c.vaultPath)
}

// AskVaultPassword asks the user to enter a password
//
// Buisiness logic:
//   - Ask the user to enter a password
//   - If the user enters an empty password, return an error
//   - Otherwise return the password
func (c *Cli) AskVaultPassword() (string, errorMessage string) {
	password, err := c.askPassword("Enter password:")

	if err != nil {
		return "", err.Error()
	}

	cfmt.Infoln("") // Blank line, for better readability

	if password == "" {
		return "", "- Password cannot be empty"
	}

	return password, ""
}

// AskVaultPasswordWithConfirm asks the user to enter a password and confirm it
//
// Buisiness logic:
//   - Ask the user to enter a password
//   - If the user enters an empty password, return an error
//   - Confirm the password to avoid any spelling mistakes
//   - If the password and confirmation do not match, return an error
//   - Otherwise return the password
func (c *Cli) AskVaultPasswordWithConfirm() (string, errorMessage string) {
	password, err := c.askPassword("Enter the password:")

	if err != nil {
		return "", err.Error()
	}

	cfmt.Infoln("") // Blank line, for better readability

	if password == "" {
		return "", "- Password cannot be empty"
	}

	passwordConfirm, err := c.askPassword("Confirm the password:")

	if err != nil {
		return "", err.Error()
	}

	cfmt.Infoln("") // Blank line, for better readability

	if password != passwordConfirm {
		return "", "- Passwords do not match"
	}

	return password, ""
}

// AskVaultPath asks the user to enter the path to the vault file
//
// Buisiness logic:
//   - Ask the user to enter the path to the vault file
//   - If the user enters an empty path, return an error
//   - To confirm its a .vault file, we check the extension
//   - If the extension is not .vault, return an error
//   - Otherwise return the file path
func (c *Cli) AskVaultPath() (string, errorMessage string) {
	filePath, err := c.askString("Enter the path to the vault file:")

	if err != nil {
		return "", err.Error()
	}

	cfmt.Infoln("") // Blank line, for better readability

	if filePath == "" {
		return "", "- File path cannot be empty"
	}

	extension := filepath.Ext(filePath)

	if extension != ".vault" {
		return "", "- File extension must be .vault"
	}

	return filePath, ""
}

// AskKeyName asks the user to enter the name of the key
//
// Buisiness logic:
//   - Ask the user to enter the name of the key
//   - If the user enters an empty name, return an error
//   - If the name contains spaces, return an error
//   - Otherwise return the name
func (c *Cli) AskKeyName() (string, errorMessage string) {
	keyName, err := c.askString("Specify the name of the key (i.e. 'DB_PASSWORD'):")

	if err != nil {
		return "", err.Error()
	}

	cfmt.Infoln("") // Blank line, for better readability

	if keyName == "" {
		return "", "- Key name cannot be empty"
	}

	if strings.Contains(keyName, " ") {
		return "", "- Key name cannot contain spaces"
	}

	return keyName, ""
}

// AskKeyValue asks the user to enter the value of the key
//
// Buisiness logic:
//   - Ask the user to enter the value of the key (allowing multiline)
//   - If the user enters an empty value, do not return an error, it is ok
//   - Otherwise return the value
func (c *Cli) AskKeyValue() (string, errorMessage string) {
	keyValue, err := c.askString("Enter the value of the key:")

	if err != nil {
		return "", err.Error()
	}

	cfmt.Infoln("") // Blank line, for better readability

	return keyValue, ""
}

func (c *Cli) askString(prompt string) (string, error) {
	cfmt.Infoln(prompt)

	key := ""
	fmt.Scanln(&key)
	key = strings.TrimSpace(key)

	if key == "" {
		return "", errors.New("string cannot be empty")
	}

	return key, nil
}

func (c *Cli) askPassword(prompt string) (string, error) {
	cfmt.Infoln(prompt)

	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))

	if err != nil {
		return "", err
	}
	password := string(passwordBytes)
	password = strings.TrimSpace(password)

	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	return password, nil
}

// FindVaultPathFromArgs finds the file path from the arguments, if provided
//
// Buisiness logic:
//   - If the arguments are empty, return an empty file path
//   - We expect the first argument to be the file path
//   - To confirm its a .vault file, we check the extension
//   - If the extension is not .vault, return an error
//   - Otherwise return the file path
//
// Parameters:
//   - args: The command line arguments (excluding the executable, and the command names)
//
// Returns:
//   - filePath: The file path
//   - errorMessage: The error message
func (c *Cli) FindVaultPathFromArgs(args []string) (filePath string, errorMessage string) {
	if len(args) < 1 {
		return "", ""
	}

	filePath = args[0]

	// Ignore flags
	if strings.HasPrefix(filePath, "-") {
		return "", ""
	}

	extension := filepath.Ext(filePath)

	if extension != ".vault" {
		return "", "- File extension must be .vault"
	}

	return filePath, ""
}

func (c *Cli) Help(_ []string) {
	cfmt.Infoln("Usage:")
	cfmt.Infoln(" - init [vaultPath] - Initialize the vault")
	cfmt.Infoln(" - key-list [vaultPath] - Lists all the keys in the vault")
	cfmt.Infoln(" - key-remove [vaultPath] - Removes a key from the vault")
	cfmt.Infoln(" - key-set [vaultPath] - Sets a key in the vault")
	cfmt.Infoln(" - ui [vaultPath] - Starts the web UI to visually edit the vault")
	cfmt.Infoln(" - encrypt - Utility function to encrypt a string")
	cfmt.Infoln(" - decrypt - Utility function to decrypt a string")
	cfmt.Infoln(" - obfuscate - Utility function to obfuscate a string")
	cfmt.Infoln(" - deobfuscate - Utility function to deobfuscate a string")
	cfmt.Infoln(" - help - Show this help")
	cfmt.Infoln("")
	cfmt.Infoln("envenc is a tool for managing encrypted environment variables")
	cfmt.Infoln("it allows you to store and retrieve environment variables in")
	cfmt.Infoln("a secure password protected vault file")
	cfmt.Infoln("")
	cfmt.Infoln("Example:")
	cfmt.Infoln("$> envenc init .env.vault")
	cfmt.Infoln("$> envenc key-set .env.vault")
	cfmt.Infoln("$> envenc key-list .env.vault")
	cfmt.Infoln("$> envenc key-remove .env.vault")
	cfmt.Infoln("$> envenc ui .env.vault")
	cfmt.Infoln("$> envenc encrypt")
	cfmt.Infoln("$> envenc decrypt")
	cfmt.Infoln("$> envenc obfuscate")
	cfmt.Infoln("$> envenc deobfuscate")
	cfmt.Infoln("")
	cfmt.Infoln("For more information visit:")
	cfmt.Infoln("")
	cfmt.Infoln("https://github.com/dracory/envenc")
}

// Run executes the command
//
// # It expects a command with the second argument being the command
//
// Buisiness logic:
//   - Parse command line arguments
//   - First argument is the name of the executable, ignore it
//   - Second argument is the command
//   - If there is no command, help is shown as default
//   - If the command is unknown, help is shown as default
//   - Otherwise execute the command
//
// Parameters
//   - args: The command line arguments
//
// Returns
//   - None
func (c *Cli) Run(args []string) {
	if len(args) < 2 {
		c.Help([]string{})
		return
	}

	command := lo.ValueOr(c.commands, args[1], c.Help)

	command(args[2:]) // remove the executable and the command names
}
