# POC: Integration with OPA [Conftest][conftest]

## Notes

1. For the POC we had to refactor [aquasecurity/appshield][appshield] Rego scripts and replace `deny[msg]` rules with
   `violation[{"msg": msg, "title": "@title"}]`.
2. Rego scripts do not provide context / metadata to identify whether checks relate to a Pod or a container. (See how we
   map [Polaris][polaris] checks to `PodChecks []Check` and `ContainerChecks map[string][]Check` properties of `ConfigAuditReport`.)
3. Conftest does not include successful checks, only warnings, failures, and successes count.
4. Conftest returns non 0 exit code in case of failures. There's no flag to override this behavior. In the POC we are
   using `confest test || true` command as a workaround.

## Starboard CLI

1. The default ConfigAuditReport scanner is Polaris. The first step is to switch over to Conftest:
   ```
   kubectl patch cm starboard -n starboard \
     --type merge \
     -p "$(cat <<EOF
   {
     "data": {
       "configAuditReports.scanner": "Conftest"
     }
   }
   EOF
   )"
   ```
2. Add Rego policy files to the `starboard` ConfigMap in the `starboard` namespace. Those are mounted at `/project/policy`
   in the file system of Pods controlled by scan jobs created by Starboard. Notice that each policy file is stored
   with the key that has the `conftest.policy.` prefix.
   ```
   kubectl create cm starboard -n starboard \
     --from-file=conftest.policy.kubernetes.rego=docs/poc/conftest/policy/kubernetes.rego \
     --from-file=conftest.policy.file_system_not_read_only.rego=docs/poc/conftest/policy/file_system_not_read_only.rego \
     --from-file=conftest.policy.uses_image_tag_latest.rego=docs/poc/conftest/policy/uses_image_tag_latest.rego \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

> **NOTE:** To delete policies you can patch the `starboard` ConfigMap with the following command:
> ```
> kubectl patch cm starboard -n starboard \
>   --type json \
>   -p '[{"op": "remove", "path": "/data/conftest.policy.uses_image_tag_latest.rego"}]'
> ```

## Starboard Operator

The commands to configure the operator are nearly the same as for CLI. The only difference is to use the
`starboard-operator` namespace instead of `starboard`.

## Quick Start

1. Create the `nginx` Deployment:
   ```
   kubectl create deploy nginx --image nginx
   ```
2. Init Starboard CLI and audit configuration of the `nginx` Deployment:
   ```
   make build-starboard-cli
   ./bin/starboard init -v 3
   ./bin/starboard scan configauditreports deploy/nginx -v 3 --delete-scan-job=false
   ```
3. List `ConfigAuditReport` instances:
   ```console
   $ kubectl get configauditreports -o wide
   NAME               SCANNER    AGE   DANGER   WARNING   PASS
   deployment-nginx   Conftest   10s   2        0         0
   ```
4. Get the `ConfigAuditReport` for the `nginx` Deployment in JSON format:
   ```console
   $ kubectl get configauditreport deployment-nginx -o jsonpath='{.report}'
   {
     "containerChecks": {},
     "podChecks": [
       {
         "category": "Security",
         "checkID": "Image tag \":latest\" used",
         "message": "container nginx of deployment nginx in default namespace should specify image tag",
         "severity": "DANGER",
         "success": false
       },
       {
         "category": "Security",
         "checkID": "Root file system is not read-only",
         "message": "container nginx of deployment nginx in default namespace should set securityContext.readOnlyRootFilesystem to true",
         "severity": "DANGER",
         "success": false
       }
     ],
     "scanner": {
       "name": "Conftest",
       "vendor": "Open Policy Agent",
       "version": "v0.23.0"
     },
     "summary": {
       "dangerCount": 2,
       "passCount": 0,
       "warningCount": 0
     },
     "updateTimestamp": "2021-03-05T22:01:08Z"
   }
   ```

[conftest]: https://github.com/open-policy-agent/conftest
[appshield]: https://github.com/aquasecurity/appshield
[polaris]: https://github.com/FairwindsOps/polaris