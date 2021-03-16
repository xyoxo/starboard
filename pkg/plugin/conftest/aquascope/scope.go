package aquascope

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/pkg/errors"
)

const (
	AquaLabel             = "aqua.label"
	AquaRegistry          = "aqua.registry"
	AquaService           = "aqua.service"
	AquaHost              = "aqua.host"
	AquaHostGroup         = "aqua.hostgroup"
	AquaServerlessProject = "aqua.serverless_project"
	ImageName             = "image.name"
	ImageLabel            = "image.label"
	ImageAuthor           = "image.author"
	ImageOS               = "image.os"
	ImageArchitecture     = "image.architecture"
	ImageEnvVar           = "image.envvar"
	ImagePrefix           = "image.prefix"
	ImageURL              = "image.url"
	ImageRepo             = "image.repo"
	ContainerName         = "container.name"
	ContainerImage        = "container.image"
	ContainerEnvVar       = "container.envvar"
	ContainerLabel        = "container.label"
	FunctionName          = "function.name"
	FunctionTag           = "function.tag"
	BuildPipeline         = "build.pipeline"
	HostName              = "os.hostname"
	HostIp                = "os.hostip"
	HostUser              = "os.user"
	HostGroup             = "os.group"
	HostType              = "os.type"
	CFAppName             = "cf.appname"
	CFSpace               = "cf.space"
	CFOrg                 = "cf.org"
	CloudProvider         = "cloud.provider"
	CloudVMName           = "cloud.vmname"
	CloudVMLocation       = "cloud.vmlocation"
	CloudVMResourceGroup  = "cloud.vmresourcegroup"
	CloudVMid             = "cloud.vmid"
	CloudVMImageID        = "cloud.vmimageid"
	CloudVMLabel          = "cloud.vmlabel"
	CloudVMIP             = "cloud.vmip"
	CloudVMSubnet         = "cloud.vmsubnet"
	CloudVMVPCID          = "cloud.vmvpcid"
	CloudVMSecurityGroups = "cloud.vmsecuritygroups"
	KubernetesCluster     = "kubernetes.cluster"
	KubernetesNamespace   = "kubernetes.namespace"
	ApplicationScopeName  = "application_scope.name"
	KubernetesDaemonset   = "kubernetes.daemonset"
	KubernetesDeployment  = "kubernetes.deployment"
	KubernetesJob         = "kubernetes.job"
	KubernetesLabel       = "kubernetes.label"
	KubernetesPod         = "kubernetes.pod"
)

type (
	ScopeTypes      map[string]ScopeType
	ScopeAttributes map[string]ScopeAttribute

	ScopeAttribute struct {
		Name            string `json:"name"`
		Display         string `json:"display"`
		Description     string `json:"description"`
		IsNameValue     bool   `json:"is_name_value"`
		IsValueOptional bool   `json:"is_value_optional"` // for cloud vm the tag/label can consist of a key only
	}

	ScopeType struct {
		Name        string          `json:"name"`
		Display     string          `json:"display"`
		Description string          `json:"description"`
		Attributes  ScopeAttributes `json:"attributes"`
	}

	Variable struct {
		Attribute string `json:"attribute"`
		Value     string `json:"value,omitempty"` //we could have one of these fields, or name or name_value
		Name      string `json:"name,omitempty"`
	}

	Scope struct {
		Expression string     `json:"expression"`
		Variables  []Variable `json:"variables"`
	}

	ScopeMatchOptions struct {
		ExactMatch bool
	}
)

func GetAvailableScopeTypes() ScopeTypes {
	return ScopeTypes{
		"kubernetes": {
			"kubernetes",
			"Kubernetes",
			"",
			ScopeAttributes{
				"namespace":  {"namespace", "Namespace", "", false, false},
				"deployment": {"deployment", "Deployment", "", false, false},
				"cluster":    {"cluster", "Cluster", "", false, false},
				"pod":        {"pod", "Pod", "", false, false},
				"label":      {"label", "Label", "", true, false},
				"daemonset":  {"daemonset", "Daemonset", "", false, false},
				"job":        {"job", "Job", "", false, false},
			},
		},
		"mesosphere": {
			"mesosphere",
			"Mesosphere",
			"",
			ScopeAttributes{
				"marathon.appid":       {"marathon.appid", "Marathon Application ID", "", false, false},
				"marathon.packagename": {"marathon.packagename", "Marathon Package Name", "", false, false},
			},
		},
		"container": {
			"container",
			"Container",
			"",
			ScopeAttributes{
				"name":   {"name", "Name", "", false, false},
				"image":  {"image", "Image", "", false, false},
				"envvar": {"envvar", "Environment Variable", "", true, false},
				"label":  {"label", "Label", "", true, false},
			},
		},
		"image": {
			"image",
			"Image",
			"",
			ScopeAttributes{
				"name":         {"name", "Name", "", false, false},
				"id":           {"id", "ID", "", false, false},
				"prefix":       {"prefix", "Registry Prefix", "", false, false},
				"url":          {"url", "Registry URL", "", false, false},
				"repo":         {"repo", "Repository", "", false, false},
				"repodigest":   {"repodigest", "Repository Digest", "", false, false},
				"envvar":       {"envvar", "Environment Variable", "", true, false},
				"label":        {"label", "Label", "", true, false},
				"author":       {"author", "Author", "", false, false},
				"os":           {"os", "OS", "", false, false},
				"architecture": {"architecture", "Architecture", "", false, false},
			},
		},
		"function": {
			"function",
			"Function",
			"",
			ScopeAttributes{
				"name": {"name", "Name", "", false, false},
				"tag":  {"tag", "Tag", "", true, false},
			},
		},
		"os": {
			"os",
			"Host",
			"",
			ScopeAttributes{
				"user":     {"user", "User", "", false, false},
				"group":    {"group", "Group", "", false, false},
				"hostname": {"hostname", "Host Name", "", false, false},
				"hostip":   {"hostip", "Host IP", "", false, false},
				"type":     {"type", "OS Type", "", false, false},
			},
		},
		"aqua": {
			"aqua",
			"Aqua",
			"",
			ScopeAttributes{
				"label":              {"label", "Label", "", false, false},
				"service":            {"service", "Service", "", false, false},
				"host":               {"host", "Host Logical Name", "", false, false},
				"hostgroup":          {"hostgroup", "Enforcer Group", "", false, false},
				"registry":           {"registry", "Registry", "", false, false},
				"serverless_project": {"serverless_project", "ServerlessApp", "", false, false},
			},
		},
		"build": {
			"build",
			"Build",
			"",
			ScopeAttributes{
				"pipeline": {"pipeline", "Pipeline", "", false, false},
			},
		},
		"cf": {
			"cf",
			"Cloud Foundry",
			"",
			ScopeAttributes{
				"appname": {"appname", "Application", "", false, false},
				"space":   {"space", "Space", "", false, false},
				"org":     {"org", "Organization", "", false, false},
			},
		},
		"cloud": {
			"cloud",
			"Cloud Attributes",
			"",
			ScopeAttributes{
				"provider":         {"provider", "Provider", "", false, false},
				"vmname":           {"vmname", "Name", "", false, false},
				"vmlocation":       {"vmlocation", "Location or Region", "", false, false},
				"vmresourcegroup":  {"vmresourcegroup", "Resource Group", "", false, false},
				"vmid":             {"vmid", "VM ID", "", false, false},
				"vmimageid":        {"vmimageid", "Image ID", "", false, false},
				"vmlabel":          {"vmlabel", "Labels or Tags", "", true, true},
				"vmip":             {"vmip", "Public IP", "", false, false},
				"vmsubnet":         {"vmsubnet", "Public IP Subnet", "", false, false},
				"vmvpcid":          {"vmvpcid", "Network ID", "", false, false},
				"vmsecuritygroups": {"vmsecuritygroups", "Security Groups", "", false, false},
			},
		},
		// NOTE: 'all' scope currently removed
		//"all": {
		//"all",
		//"All",
		//"",
		//ScopeAttributes{
		//},
		//},
	}
}

func GetAvailableHostScopeTypes() ScopeTypes {
	return ScopeTypes{
		"os": {
			"os",
			"Host",
			"",
			ScopeAttributes{
				"hostname": {"hostname", "Host Name", "", false, false},
				"type":     {"type", "OS Type", "", false, false},
			},
		},
		"aqua": {
			"aqua",
			"Aqua",
			"",
			ScopeAttributes{
				"host":      {"host", "Host Logical Name", "", false, false},
				"hostgroup": {"hostgroup", "Enforcer Group", "", false, false},
			},
		},
		// This has been copied from GetAvailableScopeTypes().
		"cloud": {
			"cloud",
			"Cloud Attributes",
			"",
			ScopeAttributes{
				"provider":         {"provider", "Provider", "", false, false},
				"vmname":           {"vmname", "Name", "", false, false},
				"vmlocation":       {"vmlocation", "Location or Region", "", false, false},
				"vmresourcegroup":  {"vmresourcegroup", "Resource Group", "", false, false},
				"vmid":             {"vmid", "VM ID", "", false, false},
				"vmimageid":        {"vmimageid", "Image ID", "", false, false},
				"vmlabel":          {"vmlabel", "Labels or Tags", "", true, true},
				"vmip":             {"vmip", "Public IP", "", false, false},
				"vmsubnet":         {"vmsubnet", "Public IP Subnet", "", false, false},
				"vmvpcid":          {"vmvpcid", "Network ID", "", false, false},
				"vmsecuritygroups": {"vmsecuritygroups", "Security Groups", "", false, false},
			},
		},
	}
}

type ScopeEval struct {
	input map[string]Variable
	scope Scope
}

func StartEval(scope Scope) *ScopeEval {
	return &ScopeEval{
		scope: scope,
		input: make(map[string]Variable),
	}
}

func (ctx *ScopeEval) WithNameValue(t string, name, value string) *ScopeEval {
	ctx.input[t] = Variable{Attribute: t, Value: value, Name: name}
	return ctx
}

func (ctx *ScopeEval) WithValue(t string, value string) *ScopeEval {
	ctx.input[t] = Variable{Attribute: t, Value: value}
	return ctx
}

func (ctx *ScopeEval) IsValidVariables(inputVars []Variable) (bool, error) {

	validScopeTypes := GetAvailableScopeTypes()
	for _, inputVar := range inputVars {

		attr := strings.SplitN(inputVar.Attribute, ".", 2)
		if len(attr) != 2 {
			return false, errors.New("for attribute you must provide value delimited by '.'")
		}
		scopeName := attr[0]
		scopeAttr := attr[1]

		// do we have valid scope
		scope, foundScope := validScopeTypes[scopeName]
		if foundScope != true {
			return false, errors.New(fmt.Sprintf("%s is not valid scope name", scopeName))
		}

		// do we contains attribute
		attrVal, foundAttrComp := scope.Attributes[scopeAttr]
		if foundAttrComp != true {
			return false, errors.New(fmt.Sprintf("%s is not valid attribute for scope %s", scopeAttr, scopeName))
		}

		// is attribute composite value
		if attrVal.IsNameValue == true {
			if inputVar.Name == "" {
				return false, errors.New(fmt.Sprintf("can not provide an empty name for attribute %s", scopeName))
			}
		}

		// is attribute simple value
		if inputVar.Value == "" && !attrVal.IsValueOptional {
			return false, errors.New(fmt.Sprintf("can not provide an empty value for attribute %s", scopeName))
		}

	}

	return true, nil

}

func (ctx *ScopeEval) Validate() (bool, error) {

	evaluatedVariables := make(map[string]interface{})
	for i := 0; i < len(ctx.scope.Variables); i++ {
		v := fmt.Sprintf("v%d", i+1)
		evaluatedVariables[v] = true
	}

	// validate that expression has no lexical errors in boolean expression
	exp, err := govaluate.NewEvaluableExpression(ctx.scope.Expression)
	if err != nil {
		return false, fmt.Errorf("expression provided is invalid, %s", err)
	}

	isValid, err := ctx.IsValidVariables(ctx.scope.Variables)
	if isValid == false {
		return false, err
	}

	for _, v := range exp.Vars() {
		if _, found := evaluatedVariables[v]; !found {
			return false, fmt.Errorf("expression variable: %s is not present in any of the scope variables", v)
		}
	}

	// validate that variables passed into boolean expression is valid
	_, err = exp.Evaluate(evaluatedVariables)
	if err != nil {
		return false, fmt.Errorf("variables provided for expression is invalid, %s", err)
	}
	return true, nil
}

func (ctx *ScopeEval) Check() (bool, error) {
	return ctx.CheckWithOptions(ScopeMatchOptions{ExactMatch: false})
}

func (ctx *ScopeEval) CheckWithOptions(options ScopeMatchOptions) (bool, error) {
	evaluatedVariables := make(map[string]interface{})
	for i := 0; i < len(ctx.scope.Variables); i++ {
		variable := ctx.scope.Variables[i]
		v := fmt.Sprintf("v%d", i+1)
		if inputVariable, ok := ctx.input[variable.Attribute]; ok {
			isMatch := match(variable.Value, inputVariable.Value, options)
			if inputVariable.Name != "" {
				isMatch = isMatch && match(variable.Name, inputVariable.Name, options)
			}
			evaluatedVariables[v] = isMatch
		} else {
			evaluatedVariables[v] = false
		}
	}
	//ctx.scope.Expression = strings.Replace(ctx.scope.Expression, "&&", "and", -1)
	//ctx.scope.Expression = strings.Replace(ctx.scope.Expression, "||", "or", -1)
	exp, err := govaluate.NewEvaluableExpression(ctx.scope.Expression)
	if err != nil {
		return false, fmt.Errorf("failed parsing expression %s", err)
	}
	res, err := exp.Evaluate(evaluatedVariables)
	if err != nil {
		return false, fmt.Errorf("failed evaluating expression %s", err)
	}
	return res.(bool), nil
}

// match return true when value reg which can include wildcards * matches
// the given value. When exactMatch is enabled, both postfix and prefix of
// the value will be determined only by reg, otherwise, any postfix
// to reg will be accepted (this flag was added to keep backwards compatibility
// where originally it was as if this flag was disabled)
func match(reg, value string, options ScopeMatchOptions) bool {
	reg = "^" + strings.Replace(reg, "*", ".*", -1)
	if options.ExactMatch {
		reg = fmt.Sprintf("%s$", reg)
	}
	matched, _ := regexp.MatchString(reg, value)
	return matched
}

// NameValueToHandler is a map that represents keys that we have to evaluate with
// name-value and not only with value.
// for each key we have matching function to split the value into name and value
// for example: functions tag. we split the name value by splitting the tag by the colon.
// value env:prod -> will be name:"env" value:"prod"

var NameValueToHandler = map[string]func(val string) (name, value string){
	FunctionTag: func(val string) (string, string) {
		tagSplit := strings.SplitN(val, ":", 2)
		if len(tagSplit) == 2 {
			return tagSplit[0], tagSplit[1]
		} else {
			return val, ""
		}
	},
}

// IsScopeMatch checks whether the given input variables match to the scope.
// The input variables are represented as attribute => value map.
func IsScopeMatch(scope Scope, inputVariables map[string]string) (bool, error) {
	return IsScopeMatchWithOptions(scope, inputVariables, ScopeMatchOptions{ExactMatch: false})
}

// IsScopeMatchWithOptions checks whether the given input variables match to the scope.
// The input variables are represented as attribute => value map.
func IsScopeMatchWithOptions(scope Scope, inputVariables map[string]string, options ScopeMatchOptions) (bool, error) {
	if scope.Expression == "" {
		return false, nil
	}

	match := false

	eval := StartEval(scope)
	for attribute, value := range inputVariables {
		// check if we have to parse the value to name value
		if handler, exist := NameValueToHandler[attribute]; exist {
			name, val := handler(value)
			eval.WithNameValue(attribute, name, val)
		} else {
			eval.WithValue(attribute, value)
		}
	}

	var err error
	match, err = eval.CheckWithOptions(options)
	if err != nil {
		return match, err
	}

	return match, nil
}
