package aquascope

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrueScope(t *testing.T) {
	scope := Scope{
		Expression: "(v1 && v2) && !v3 && v4",
		Variables: []Variable{
			{Attribute: "aqua.label", Value: "abc*"},
			{Attribute: "kubernetes.namespace", Value: "*amir"},
			{Attribute: "os.user", Value: "nazem"},
			{Attribute: "container.envvar", Name: "aqua_db", Value: "scal*"},
		},
	}

	valid, err := StartEval(scope).
		WithValue("aqua.label", "abc_love").
		WithValue("kubernetes.namespace", "nginx.amir").
		WithValue("os.user", "root").
		WithNameValue("container.envvar", "aqua_db", "scalock").
		Check()

	if err != nil {
		t.Errorf("error %s", err)
	}
	if !valid {
		t.Error("Test failed, scope should be matched! ")
	}
}

func TestFalseScope(t *testing.T) {
	scope := Scope{
		Expression: "(v1 && v2) && (v3 || !v4)",
		Variables: []Variable{
			{Attribute: "aqua.label", Value: "abc*"},
			{Attribute: "kubernetes.namespace", Value: "*amir"},
			{Attribute: "os.user", Value: "nazem"},
			{Attribute: "container.envvar", Name: "aqua_db", Value: "scal*"},
		},
	}

	valid, err := StartEval(scope).
		WithValue("aqua.label", "abc_love").
		WithValue("kubernetes.namespace", "nginx.amir").
		WithValue("os.user", "root").
		WithNameValue("container.envvar", "aqua_db", "scalock").
		Check()

	if err != nil {
		t.Errorf("error %s", err)
	}
	if valid {
		t.Error("Test failed, scope should be matched! ")
	}
}

func TestValidateScope(t *testing.T) {
	scope := Scope{
		Expression: "(v1 && v2) && (v3) && v4",
		Variables: []Variable{
			{Attribute: "aqua.label", Value: "abc*"},
			{Attribute: "kubernetes.namespace", Value: "*amir"},
			{Attribute: "os.user", Value: "nazem"},
			{Attribute: "container.envvar", Name: "aqua_db", Value: "scal*"},
		},
	}

	valid, err := StartEval(scope).Validate()

	if err != nil {
		t.Errorf("error %s", err)
	} else if !valid {
		t.Error("Test failed, invalid expression! ")
	}
}

func TestInputVariableNotProvidedInOr(t *testing.T) {
	scope := Scope{
		Expression: "(v1 || v2)",
		Variables: []Variable{
			{Attribute: "aqua.label", Value: "abc"},
			{Attribute: "container.evvar", Name: "some-env-var", Value: "some-value"},
		},
	}

	match, err := StartEval(scope).
		WithValue("aqua.label", "abc").
		Check()

	if err != nil {
		t.Errorf("error %s", err)
	} else if !match {
		t.Error("Test failed, expected match: true. ")
	}
}

func TestInputVariableNotProvidedInAnd(t *testing.T) {
	scope := Scope{
		Expression: "(v1 && v2)",
		Variables: []Variable{
			{Attribute: "aqua.label", Value: "abc"},
			{Attribute: "container.evvar", Name: "some-env-var", Value: "some-value"},
		},
	}

	match, err := StartEval(scope).
		WithValue("aqua.label", "abc").
		Check()

	if err != nil {
		t.Errorf("error %s", err)
	} else if match {
		t.Error("Test failed, expected match: false ")
	}
}

func TestIsScopeMatchWithOptions_ImageName(t *testing.T) {
	type testArgs struct {
		scope          Scope
		inputVariables map[string]string
		options        ScopeMatchOptions
	}
	tests := []struct {
		testName string
		args     testArgs
		want     bool
	}{
		{
			testName: "Match with wildcard postfix",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "alpine*",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "alpine:3.3",
				},
			},
			want: true,
		},
		{
			testName: "Wilcard postfix, Value has other prefix",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "alpine*",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "prefix-alpine:3.3",
				},
			},
			want: false,
		},
		{
			testName: "No match with wildcard postfix",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "alpine*",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "nginx:latest",
				},
			},
			want: false,
		},
		{
			testName: "Wildcard is the only value",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "*",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "nginx:latest",
				},
			},
			want: true,
		},
		{
			testName: "Wildcard prefix and postfix, with match",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "*alpine*",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "prefix-alpine-postfix:3.3",
				},
			},
			want: true,
		},
		{
			testName: "Wildcard prefix, with match",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "*alpine",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "prefix-alpine3.3",
				},
			},
			want: true,
		},
		{
			testName: "Wildcard prefix, no match",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "*alpine",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "prefix-nginx.3",
				},
			},
			want: false,
		},
		{
			testName: "Wildcard prefix and postfix, no match",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "*alpine*",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "prefix-nginx-postfix:3.3",
				},
			},
			want: false,
		},
		{
			testName: "Exact value, with match",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "alpine:3.3",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "alpine:3.3",
				},
			},
			want: true,
		},
		{
			testName: "Exact value, no match",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "alpine:3.2",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "alpine:3.3",
				},
			},
			want: false,
		},
		{
			testName: "Exact value, no match",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageName,
							Value:     "alpine:3.2",
						},
					},
				},
				inputVariables: map[string]string{
					ImageName: "alpine:3.3",
				},
			},
			want: false,
		},
		{
			testName: "Name Value, no match ",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: FunctionTag,
							Name:      "env",
							Value:     "prod",
						},
					},
				},
				inputVariables: map[string]string{
					FunctionTag: "no:match",
				},
			},
			want: false,
		},
		{
			testName: "Name Value wildcard name",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: FunctionTag,
							Name:      "env*",
							Value:     "prod",
						},
					},
				},
				inputVariables: map[string]string{
					FunctionTag: "environment:prod",
				},
			},
			want: true,
		},
		{
			testName: "Name Value wildcard value",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: FunctionTag,
							Name:      "env",
							Value:     "prod*",
						},
					},
				},
				inputVariables: map[string]string{
					FunctionTag: "env:production",
				},
			},
			want: true,
		},
		{
			testName: "Name Value wildcard name value",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: FunctionTag,
							Name:      "env*",
							Value:     "prod*",
						},
					},
				},
				inputVariables: map[string]string{
					FunctionTag: "environment:production",
				},
			},
			want: true,
		},
		{
			testName: "Name Value wildcard name - fail",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: FunctionTag,
							Name:      "env*",
							Value:     "prod",
						},
					},
				},
				inputVariables: map[string]string{
					FunctionTag: "fail:prod",
				},
			},
			want: false,
		},
		{
			testName: "Name Value match ",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: FunctionTag,
							Name:      "env",
							Value:     "prod",
						},
					},
				},
				inputVariables: map[string]string{
					FunctionTag: "env:prod",
				},
			},
			want: true,
		},
		{
			testName: "Exact Match False: postfix is allowed",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageRepo,
							Name:      "",
							Value:     "alpine",
						},
					},
				},
				inputVariables: map[string]string{
					ImageRepo: "alpine-and-postfix",
				},
				options: ScopeMatchOptions{ExactMatch: false},
			},
			want: true,
		},
		{
			testName: "Exact Match True: postfix is disallowed",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageRepo,
							Name:      "",
							Value:     "alpine",
						},
					},
				},
				inputVariables: map[string]string{
					ImageRepo: "alpine-and-postfix",
				},
				options: ScopeMatchOptions{ExactMatch: true},
			},
			want: false,
		},
		{
			testName: "Exact Match False: prefix is allowed",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageRepo,
							Name:      "",
							Value:     "alpine",
						},
					},
				},
				inputVariables: map[string]string{
					ImageRepo: "prefix-and-alpine",
				},
				options: ScopeMatchOptions{ExactMatch: false},
			},
			want: false,
		},
		{
			testName: "Exact Match True: postfix is disallowed",
			args: testArgs{
				scope: Scope{
					Expression: "v1",
					Variables: []Variable{
						{
							Attribute: ImageRepo,
							Name:      "",
							Value:     "alpine",
						},
					},
				},
				inputVariables: map[string]string{
					ImageRepo: "prefix-and-alpine",
				},
				options: ScopeMatchOptions{ExactMatch: true},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf(tt.testName), func(t *testing.T) {
			got, err := IsScopeMatchWithOptions(tt.args.scope, tt.args.inputVariables, tt.args.options)
			assert.Nil(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
