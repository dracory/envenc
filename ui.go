package envenc

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/dracory/api"
	"github.com/dracory/cdn"
	"github.com/dracory/hb"
	"github.com/dracory/websrv"

	"github.com/mingrammer/cfmt"
	"github.com/samber/lo"
)

type ui struct {
	vaultPath string
}

func (u *ui) Run(args []string) {
	mappedArgs := u.argsToMap(args)
	address := lo.ValueOr(mappedArgs, "address", "127.0.0.1:38080")
	cfmt.Infoln("Listening on: http://" + address)

	s := websrv.New(address, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(u.router(w, r)))
	})

	err := s.Start()

	if err != nil {
		panic(err)
	}
}

func (u *ui) apiKeys(w http.ResponseWriter, r *http.Request) string {
	w.Header().Set("Content-Type", "application/json")

	vault := strings.TrimSpace(u.req(r, "vault", ""))
	password := strings.TrimSpace(u.req(r, "password", ""))

	if vault == "" {
		return api.Error("Vault file is required").ToString()
	}

	if password == "" {
		return api.Error("Password is required").ToString()
	}

	if !u.fileExists(vault) {
		return api.Error("Vault file does not exist").ToString()
	}

	keys, err := KeyListFromFile(vault, password)

	if err != nil {
		return api.Error(err.Error()).ToString()
	}

	// delete id, as it is reserved
	delete(keys, "id")

	return api.SuccessWithData("Keys successful", map[string]any{
		"keys": keys,
	}).ToString()
}

func (u *ui) apiKeyAdd(w http.ResponseWriter, r *http.Request) string {
	w.Header().Set("Content-Type", "application/json")

	vault := strings.TrimSpace(u.req(r, "vault", ""))
	password := strings.TrimSpace(u.req(r, "password", ""))
	key := strings.TrimSpace(u.req(r, "key", ""))
	value := strings.TrimSpace(u.req(r, "value", ""))

	if vault == "" {
		return api.Error("Vault file is required").ToString()
	}

	if password == "" {
		return api.Error("Password is required").ToString()
	}

	if key == "" {
		return api.Error("Key is required").ToString()
	}

	if !u.fileExists(vault) {
		return api.Error("Vault file does not exist").ToString()
	}

	exists, err := KeyExists(vault, password, key)

	if err != nil {
		return api.Error(err.Error()).ToString()
	}

	if exists {
		return api.Error("Key already exists").ToString()
	}

	if err := KeySet(vault, password, key, value); err != nil {
		return api.Error(err.Error()).ToString()
	}

	return api.Success("Key added successfully").ToString()
}

func (u *ui) apiKeyRemove(w http.ResponseWriter, r *http.Request) string {
	w.Header().Set("Content-Type", "application/json")

	vault := strings.TrimSpace(u.req(r, "vault", ""))
	password := strings.TrimSpace(u.req(r, "password", ""))
	key := strings.TrimSpace(u.req(r, "key", ""))

	if vault == "" {
		return api.Error("Vault file is required").ToString()
	}

	if password == "" {
		return api.Error("Password is required").ToString()
	}

	if key == "" {
		return api.Error("Key is required").ToString()
	}

	if key == "id" {
		return api.Error("Key 'id' cannot be removed, it is a reserved key.").ToString()
	}

	if !u.fileExists(vault) {
		return api.Error("Vault file does not exist").ToString()
	}

	if err := KeyRemove(vault, password, key); err != nil {
		return api.Error(err.Error()).ToString()
	}

	return api.Success("Key removed successfully").ToString()
}

func (u *ui) apiKeyUpdate(w http.ResponseWriter, r *http.Request) string {
	w.Header().Set("Content-Type", "application/json")

	vault := strings.TrimSpace(u.req(r, "vault", ""))
	password := strings.TrimSpace(u.req(r, "password", ""))
	key := strings.TrimSpace(u.req(r, "key", ""))
	value := strings.TrimSpace(u.req(r, "value", ""))

	if vault == "" {
		return api.Error("Vault file is required").ToString()
	}

	if password == "" {
		return api.Error("Password is required").ToString()
	}

	if key == "" {
		return api.Error("Key is required").ToString()
	}

	if !u.fileExists(vault) {
		return api.Error("Vault file does not exist").ToString()
	}

	if err := KeySet(vault, password, key, value); err != nil {
		return api.Error(err.Error()).ToString()
	}

	return api.Success("Key updated successfully").ToString()
}

func (u *ui) apiLogin(w http.ResponseWriter, r *http.Request) string {
	w.Header().Set("Content-Type", "application/json")

	vault := strings.TrimSpace(u.req(r, "vault", ""))
	password := strings.TrimSpace(u.req(r, "password", ""))

	if vault == "" {
		return api.Error("Vault file is required").ToString()
	}

	if password == "" {
		return api.Error("Password is required").ToString()
	}

	if !u.fileExists(vault) {
		return api.Error("Vault file does not exist").ToString()
	}

	data, err := KeyListFromFile(vault, password)

	if err != nil {
		return api.Error(err.Error()).ToString()
	}

	return api.SuccessWithData("Login successful", map[string]any{
		"keys": data,
	}).ToString()
}

func (u *ui) app() string {
	vaultPathJSON, _ := u.toJSON(u.vaultPath)
	h := `
const vaultPath = ` + vaultPathJSON + `;
Vue.createApp({
	data() {
		return {
			pageKeysShow: false,
			pageLoginShow: true,
			keys: [],
			vaultPath: "",
			vaultPassword: "",
			keyAddForm: {
				key: "",
				value: "",
				errorMessage: "",
			},
			keyUpdateForm: {
				key: "",
				value: "",
				errorMessage: "",
			},
			keyRemoveForm: {
				key: "",
				errorMessage: "",
			},
			loginForm: {
				vault: vaultPath,
				password: "",
				errorMessage: "",
			},
		}
	},
	methods: {
		keyAdd() {
			$.post("?a=key-add", {
				vault: this.vaultPath,
				password: this.vaultPassword,
				key: this.keyAddForm.key,
				value: this.keyAddForm.value
			}).done((response) => {
				if (response.status != "success") {
					this.keyAddForm.errorMessage = response.message;
					return;
				}
					
				this.keyAddForm.key = "";
				this.keyAddForm.value = "";
				this.keysList();
				this.keyAddModalClose();
			}).fail((data) => {
				this.keyAddForm.errorMessage = "Adding key failed";
			})
		},
		keyAddModal() {
			$("#ModalKeyAdd").modal().show();
		},
		keyAddModalClose() {
			$("#ModalKeyAdd").modal().hide();
		},
		keyUpdate() {
			$.post("?a=key-update", {
				vault: this.vaultPath,
				password: this.vaultPassword,
				key: this.keyUpdateForm.key,
				value: this.keyUpdateForm.value
			}).done((response) => {
				if (response.status != "success") {
					this.keyUpdateForm.errorMessage = response.message;
					return;
				}
				this.keyUpdateForm.key = "";
				this.keyUpdateForm.value = "";
				this.keysList();
				this.keyUpdateModalClose();
			}).fail((data) => {
				this.keyUpdateForm.errorMessage = "Updating key failed";
			})
		},
		keyUpdateModalShow(key) {
			this.keyUpdateForm.key = key
			this.keyUpdateForm.value = this.keys[key]
			$("#ModalKeyUpdate").modal().show();
		},
		keyUpdateModalClose() {
			$("#ModalKeyUpdate").modal().hide();
		},
		keyRemoveModalShow(key) {
			this.keyRemoveForm.key = key
			$("#ModalKeyRemove").modal().show();
		},
		keyRemoveModalClose() {
			$("#ModalKeyRemove").modal().hide();
		},
		keyRemove() {
			$.post("?a=key-remove", {
				vault: this.vaultPath,
				password: this.vaultPassword,
				key: this.keyRemoveForm.key
			}).done((response) => {
				if (response.status != "success") {
					this.keyRemoveForm.errorMessage = response.message;
					return;
				}

				this.keyRemoveForm.key = "";
				this.keyRemoveForm.errorMessage = "";
				this.keyRemoveModalClose();
				this.keysList()
			}).fail((data) => {
				this.keyRemoveForm.errorMessage = "Removing key failed";
			})
		},
		keysList() {
		   $.post("?a=keys", {
			   vault: this.vaultPath,
			   password: this.vaultPassword
		   }).done((response) => {
			   if (response.status != "success") {
				   this.loginForm.errorMessage = response.message;
				   this.keys = [];
				   this.pageKeysShow = false;
				   this.pageLoginShow = true;
				   return;
			   }

			   this.keys = response.data.keys
		   }).fail((data) => {
			   this.loginForm.errorMessage = "Listing keys failed";
		   })
		},
		login() {
			this.loginForm.errorMessage = ""

			$.post("?a=login", {
				vault: this.loginForm.vault,
				password: this.loginForm.password
			}).done((response) => {
				if (response.status != "success") {			
					this.loginForm.errorMessage = response.message;
					return;
				}

				this.pageKeysShow = true;
				this.pageLoginShow = false;
				this.keys = response.data.keys;
				this.vaultPath = this.loginForm.vault;
				this.vaultPassword = this.loginForm.password;
			}).fail((data) => {
				this.loginForm.errorMessage = "Login failed";
			})
		}
	}
}).mount("#app")
	`
	return h
}

func (u *ui) appPage(w http.ResponseWriter, r *http.Request) string {
	divApp := hb.Div().
		ID("app").
		Child(u.pageLogin()).
		Child(u.pageKeys())
	page := hb.NewWebpage()
	page.StyleURL(cdn.BootstrapUnitedCss_5_3_3())
	page.ScriptURL(cdn.BootstrapJs_5_3_3())
	page.StyleURL(cdn.BootstrapIconsCss_1_11_3())
	page.ScriptURL(cdn.Htmx_2_0_0())
	page.ScriptURL(cdn.VueJs_3())
	page.ScriptURL(cdn.Jquery_3_7_1())
	page.Script(u.app())
	page.Child(divApp)
	return page.ToHTML()
}

func (u *ui) modalKeyAdd() hb.TagInterface {
	buttonKeyAdd := hb.Button().
		Class("btn btn-primary").
		Text("Save").
		Attr("v-on:click", "keyAdd()")
	buttonModalClose := hb.Button().
		Class("btn btn-secondary").
		Text("Close").
		Attr("v-on:click", "keyAddModalClose()")

	return hb.Div().
		ID("ModalKeyAdd").
		Class("modal").
		Child(hb.Div().
			Class("modal-dialog").
			Child(hb.Div().
				Class("modal-content").
				Child(hb.Div().
					Class("modal-header").
					Child(hb.H2().
						Style("margin: 0px;").
						Text("Add key"))).
				Child(hb.Div().
					Class("modal-body").
					Child(hb.Div().
						Class("form-group alert alert-danger").
						Attr("v-if", "keyAddForm.errorMessage").
						Child(hb.Span().Class("text-danger").Text("{{ keyAddForm.errorMessage }}")),
					).
					Child(hb.Div().
						Class("form-group").
						Child(hb.Label().
							Class("form-label").
							Text("Key")).
						Child(hb.Input().
							Class("form-control").
							Attr("type", "text").
							Attr("v-model", "keyAddForm.key"),
						),
					).
					Child(hb.Div().
						Class("form-group mt-3").
						Child(hb.Label().
							Class("form-label").
							Text("Value")).
						Child(hb.TextArea().
							Class("form-control").
							Attr("v-model", "keyAddForm.value"),
						),
					)).
				Child(
					hb.Div().
						Class("modal-footer justify-content-between").
						Child(buttonModalClose).
						Child(buttonKeyAdd),
				),
			),
		)
}

func (u *ui) modalKeyRemove() hb.TagInterface {
	buttonKeyRemove := hb.Button().
		Class("btn btn-danger").
		Text("Delete").
		Attr("v-on:click", "keyRemove()")
	buttonModalClose := hb.Button().
		Class("btn btn-secondary").
		Text("Close").
		Attr("v-on:click", "keyRemoveModalClose()")

	return hb.Div().
		ID("ModalKeyRemove").
		Class("modal").
		Child(hb.Div().
			Class("modal-dialog").
			Child(hb.Div().
				Class("modal-content").
				Child(hb.Div().
					Class("modal-header").
					Child(hb.H2().
						Style("margin: 0px;").
						Text("Remove key"))).
				Child(hb.Div().
					Class("modal-body").
					Child(hb.Div().
						Class("form-group").
						Attr("v-if", "keyRemoveForm.errorMessage").
						Child(hb.Span().Class("text-danger").Text("{{ keyRemoveForm.errorMessage }}")),
					).
					Child(hb.Div().
						Class("text-danger mb-3").
						Text("Are you sure you want to remove key '{{ keyRemoveForm.key }}'?"),
					).
					Child(hb.Div().
						Class("text-danger mb-3").
						Text("This action cannot be undone."),
					).
					Child(hb.Div().
						Class("form-group d-none").
						Child(hb.Label().
							Class("form-label").
							Text("Key")).
						Child(hb.Input().
							Class("form-control").
							Attr("type", "text").
							Attr("v-model", "keyRemoveForm.key").
							Attr("readonly", "readonly"),
						),
					)).
				Child(
					hb.Div().
						Class("modal-footer justify-content-between").
						Child(buttonModalClose).
						Child(buttonKeyRemove),
				),
			),
		)
}

func (u *ui) modalKeyUpdate() hb.TagInterface {
	buttonKeyUpdate := hb.Button().
		Class("btn btn-primary").
		Text("Save").
		Attr("v-on:click", "keyUpdate(key)")
	buttonModalClose := hb.Button().
		Class("btn btn-secondary").
		Text("Close").
		Attr("v-on:click", "keyUpdateModalClose()")

	return hb.Div().
		ID("ModalKeyUpdate").
		Class("modal").
		Child(hb.Div().
			Class("modal-dialog").
			Child(hb.Div().
				Class("modal-content").
				Child(hb.Div().
					Class("modal-header").
					Child(hb.H2().
						Style("margin: 0px;").
						Text("Update key"))).
				Child(hb.Div().
					Class("modal-body").
					Child(hb.Div().
						Class("form-group alert alert-danger").
						Attr("v-if", "keyUpdateForm.errorMessage").
						Child(hb.Span().Class("text-danger").Text("{{ keyUpdateForm.errorMessage }}")),
					).
					Child(hb.Div().
						Class("form-group").
						Child(hb.Label().
							Class("form-label").
							Text("Key")).
						Child(hb.Input().
							Class("form-control").
							Style("background-color: #e9ecef;").
							Attr("type", "text").
							Attr("v-model", "keyUpdateForm.key").
							Attr("readonly", "readonly"),
						),
					).
					Child(hb.Div().
						Class("form-group mt-3").
						Child(hb.Label().
							Class("form-label").
							Text("Value")).
						Child(hb.TextArea().
							Class("form-control").
							Attr("v-model", "keyUpdateForm.value"),
						),
					)).
				Child(
					hb.Div().
						Class("modal-footer justify-content-between").
						Child(buttonModalClose).
						Child(buttonKeyUpdate),
				),
			),
		)
}

func (u *ui) pageKeys() hb.TagInterface {
	buttonKeyNew := hb.Button().
		Class("btn btn-success float-end").
		Child(hb.I().Class("bi bi-plus-circle me-2").Attr("aria-hidden", "true")).
		Text("New key").
		Attr("v-on:click", "keyAddModal()")

	title := hb.H1().
		Text("Keys").
		Child(buttonKeyNew)

	table := hb.Table().
		// Attr("v-if", "keys.length > 0").
		Class("table").
		Child(hb.Thead().
			Child(hb.TR().
				Child(hb.TH().Style("width: 1px;").Text("Key")).
				Child(hb.TH().Text("Value")).
				Child(hb.TH().Style("width: 100px;").Text("Actions")),
			),
		).
		Child(hb.Tbody().
			Child(hb.TR().
				Attr("v-for", "key in Object.keys(keys)").
				Child(hb.TD().Text("{{ key }}")).
				Child(hb.TD().Child(hb.PRE().Text("{{ keys[key].substr(0, 100) }}")).Child(hb.Span().Attr("v-if", "keys[key].length > 100").Text("..."))).
				Child(hb.TD().
					Child(hb.Button().
						Class("btn btn-info btn-sm me-2").
						Child(hb.I().Class("bi bi-pencil-square").Attr("aria-hidden", "true")).
						Title("Update").
						Attr("v-on:click", "keyUpdateModalShow(key)")).
					Child(hb.Button().
						Class("btn btn-danger btn-sm").
						Child(hb.I().Class("bi bi-trash").Attr("aria-hidden", "true")).
						Title("Delete").
						Attr("v-on:click", "keyRemoveModalShow(key)"))),
			),
		)

	return hb.Template().
		Attr("v-if", "pageKeysShow").
		Child(hb.Div().
			Class("container").
			Style("min-height:100vh").
			Style("margin-top:50px; margin-bottom:50px;").
			Child(title).
			Child(table).
			Child(u.modalKeyAdd()).
			Child(u.modalKeyRemove()).
			Child(u.modalKeyUpdate()))
}

func (u *ui) router(w http.ResponseWriter, r *http.Request) string {
	action := u.req(r, "a", "")
	route := "/" + action

	router := map[string]func(w http.ResponseWriter, r *http.Request) string{
		"/key-add":    u.apiKeyAdd,
		"/key-update": u.apiKeyUpdate,
		"/key-remove": u.apiKeyRemove,
		"/keys":       u.apiKeys,
		"/login":      u.apiLogin,
		"/":           u.appPage,
	}

	if v, ok := router[route]; ok {
		return v(w, r)
	}

	return u.appPage(w, r)
}

func (u *ui) pageLogin() hb.TagInterface {
	buttonLogin := hb.Button().
		Class("btn btn-primary btn-lg mt-3 w-100").
		Text("Login").
		Attr("v-on:click", "login()")

	inputPassword := hb.Input().
		Class("form-control").
		Type(hb.TYPE_PASSWORD).
		Attr("v-model", "loginForm.password")

	inputVault := hb.Input().
		Class("form-control").
		Type(hb.TYPE_TEXT).
		Attr("v-model", "loginForm.vault")

	errorMessage := hb.Div().
		Class("alert alert-danger").
		Attr("v-if", "loginForm.errorMessage").
		Text("{{ loginForm.errorMessage }}")

	groupVault := hb.Div().
		Class("form-group mb-3").
		Child(hb.Label().
			Class("form-label").
			Text("Vault file path")).
		Child(inputVault)

	groupPassword := hb.Div().
		Class("form-group mb-3").
		Child(hb.Label().
			Class("form-label").
			Text("Vault file password")).
		Child(inputPassword)

	return hb.Template().
		Attr("v-if", "pageLoginShow").
		Child(
			hb.Div().
				Class("container").
				Style("margin-top:50px; margin-bottom:50px;").
				Style("height:100vh;").
				Style("display:flex;").
				Style("align-items:center;").
				Style("justify-content:center;").
				Child(hb.Div().
					Class("card").
					Style("width:100%;").
					Style("max-width:600px;").
					Child(hb.Div().
						Class("card-header").
						Child(hb.H1().
							Style("margin:0px;").
							Text("🔐 Login"))).
					Child(hb.Div().
						Class("card-body").
						Child(errorMessage).
						Child(groupVault).
						Child(groupPassword).
						Child(buttonLogin))))
}

// Req returns a POST or GET key, or default if not exists
func (u *ui) req(r *http.Request, key string, defaultValue string) string {
	postValue := r.FormValue(key)

	if len(postValue) > 0 {
		return postValue
	}

	getValue := r.URL.Query().Get(key)

	if len(getValue) > 0 {
		return getValue
	}

	return defaultValue
}

func (ui *ui) fileExists(filePath string) bool {
	_, err := os.Stat(filePath)

	return !os.IsNotExist(err)
}

// ArgsToMap converts command line arguments to a key value map
// supports filled (i.e. --user=12) and unfilled (i.e. --force) arguments
func (u *ui) argsToMap(args []string) map[string]string {
	kv := map[string]string{}
	for i := 0; i < len(args); i++ {
		current := args[i]

		if strings.HasPrefix(current, "--") {
			if strings.Contains(current, "=") {
				currentArray := strings.Split(current, "=")
				kv[currentArray[0][2:]] = currentArray[1]
			} else {
				next := ""
				if len(args) > i+1 {
					next = args[i+1]
				}

				if strings.HasPrefix(next, "--") {
					kv[current[2:]] = ""
					continue
				}
				kv[current[2:]] = next
			}
		}
	}
	return kv
}

func (u *ui) toJSON(value interface{}) (string, error) {
	jsonValue, jsonError := json.Marshal(value)
	if jsonError != nil {
		return "", jsonError
	}

	return string(jsonValue), nil
}
