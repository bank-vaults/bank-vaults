#!/bin/bash
#
# Validate Bank-Vaults configuration CRUD to make sure the creation and deletion work as expected.
# It will be used in the CI pipelines. This is the first iteration, and in the next iteration it could be replaced
# with a testing freamwork/library. "Terratest" could be a good candidate for that.

log_level=${LOG_LEVEL:-'info'}

set -euo pipefail

if [ "${log_level,,}" == 'debug' ]; then
  set -x
fi

bank_vaults_config_key="${1}"
bank_vaults_config_file_orig="scripts/validate-config-crud/vault-config.yml"
bank_vaults_config_file="${BANK_VAULTS_CONFIG_FILE:-/tmp/vault-config.yml}"

# A hacky way to use "yq" to get a section from a YAML and keeping the key used in the query.
bank_vaults_config_copy_section () {
  local key_name="${1}"

  key_value="$(yq .\"${key_name}\" ${bank_vaults_config_file_orig})" \
    yq --null-input '.'\"${key_name}\"' = env(key_value)'
}

# Create bank-vaults config with specific section(s).
bank_vaults_config_copy () {
  # Note: To ignore the indentation of "Here-Document" inside the cat command,
  # tabs are used before all lines till 2nd EOF. Make sure to use tabs (and tabs only) otherwise it will not work.
  cat <<-EOF > "${bank_vaults_config_file}"
		`
		bank_vaults_config_copy_section "purgeUnmanagedConfig"
		for key_name in ${1}; do
			bank_vaults_config_copy_section "${key_name}";
		done
		`
	EOF

  cat "${bank_vaults_config_file}"
  sleep 1
}

# Bank-Vaults watchs the actual file change not changes in the file so here we mimic creating a new file.
bank_vaults_config_touch () {
  cp -a "${bank_vaults_config_file}" "${bank_vaults_config_file}.tmp"
  cat "${bank_vaults_config_file}.tmp" > "${bank_vaults_config_file}"
  rm "${bank_vaults_config_file}.tmp"

  sleep 1
}

test_case_passed () {
  echo "[PASSED] Test case successfully passed."
}


#
# Test group - Audit
#
audit_test () {
  bank_vaults_config_copy "audit"
  local get_vault_values_json='vault audit list -format=json'

  #
  ## Case 1.
  echo -e "\nCase 1: Check audit in the config have been added."

  test "$(${get_vault_values_json} | jq -r '."audit_foo/".type')" == "file"; test_case_passed
  test "$(${get_vault_values_json} | jq -r '."audit_bar/".type')" == "file"; test_case_passed
  # If the "path" key is not defined, then the "type" value should be used as "path".
  test "$(${get_vault_values_json} | jq -r '."file/".type')" == "file"; test_case_passed

  #
  ## Case 2.
  echo -e "\nCase 2: Vault config removed when purgeUnmanagedConfig is enabled."

  # 2.1. Remove audit from the config.
  yq -i 'del(.audit[] | select(.path == "audit_foo"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 2.2. Check the removed audit is NOT in Vault.
  test "$(${get_vault_values_json} | jq -r '."audit_foo/".type')" == "null"; test_case_passed

  #
  ## Case 3.
  echo -e "\nCase 3: Vault config exists when the config excluded in purgeUnmanagedConfig."

  # 3.1. Disable purge for audit.
  yq -i '.purgeUnmanagedConfig.exclude.audit = true' "${bank_vaults_config_file}"

  # 3.2. Remove audit from the config.
  yq -i 'del(.audit[] | select(.path == "audit_bar"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 3.3. Check the removed audit is IN Vault.
  test "$(${get_vault_values_json} | jq -r '."audit_bar/".type')" == "file"; test_case_passed

  #
  ## Success.
  echo "All audit test cases have been passed."
}


#
# Test group - Auth
#
auth_test () {
  bank_vaults_config_copy "auth"
  local get_vault_values_json='vault auth list -format=json'

  #
  ## Case 1.
  echo -e "\nCase 1: Check auths in the config have been added."

  test "$(${get_vault_values_json} | jq -r '."auth_foo/".type')" == "approle"; test_case_passed
  test "$(${get_vault_values_json} | jq -r '."auth_bar/".type')" == "userpass"; test_case_passed
  # If the "path" key is not defined, then the "type" value should be used as "path".
  test "$(${get_vault_values_json} | jq -r '."userpass/".type')" == "userpass"; test_case_passed

  #
  ## Case 2.
  echo -e "\nCase 2: Vault config removed when purgeUnmanagedConfig is enabled."

  # 2.1. Remove auth from the config.
  yq -i 'del(.auth[] | select(.path == "auth_foo"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 2.2. Check the removed auth is NOT in Vault.
  test "$(${get_vault_values_json} | jq -r '."auth_foo/".type')" == "null"; test_case_passed

  #
  ## Case 3.
  echo -e "\nCase 3: Vault config exists when the config excluded in purgeUnmanagedConfig."

  # 3.1. Disable purge for auth.
  yq -i '.purgeUnmanagedConfig.exclude.auth = true' "${bank_vaults_config_file}"

  # 3.2. Remove auth from the config.
  yq -i 'del(.auth[] | select(.path == "auth_bar"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 3.3. Check the removed auth is IN Vault.
  test "$(${get_vault_values_json} | jq -r '."auth_bar/".type')" == "userpass"; test_case_passed

  #
  ## Success.
  echo "All auth test cases have been passed."
}


#
# Test group - Groups
#
groups_test () {
  bank_vaults_config_copy 'groups'
  local get_vault_values_json='vault list -format=json identity/group/name'

  #
  ## Case 1.
  echo -e "\nCase 1: Check groups in the config have been added."

  test "$(${get_vault_values_json} | jq -r '.[] | select(. == "group_foo")')" == "group_foo"; test_case_passed
  test "$(${get_vault_values_json} | jq -r '.[] | select(. == "group_bar")')" == "group_bar"; test_case_passed

  #
  ## Case 2.
  echo -e "\nCase 2: Vault config removed when purgeUnmanagedConfig is enabled."

  # 2.1. Remove group from the config.
  yq -i 'del(.groups[] | select(.name == "group_foo"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 2.2. Check the removed group is NOT in Vault.
  test "$(${get_vault_values_json} | jq -r '.[] | select(. == "group_foo")')" == ""; test_case_passed

  #
  ## Case 3.
  echo -e "\nCase 3: Vault config exists when the config excluded in purgeUnmanagedConfig."

  # 3.1. Disable purge for group.
  yq -i '.purgeUnmanagedConfig.exclude.groups = true' "${bank_vaults_config_file}"

  # 3.2. Remove group from the config.
  yq -i 'del(.groups[] | select(.name == "group_bar"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 3.3. Check the removed group is IN Vault.
  test "$(${get_vault_values_json} | jq -r '.[] | select(. == "group_bar")')" == "group_bar"; test_case_passed

  #
  ## Success.
  echo "All groups test cases have been passed."
}


#
# Test group - Group-Aliases
#
group_aliases_test () {
  # NOTE: group-aliases has a different test style because Vault exposes only group-aliases IDs not the names directly.
  bank_vaults_config_copy 'auth groups group-aliases'

  group_aliases_ids () {
    vault list -format=json identity/group-alias/id | jq -r '.[]'
  }

  #
  ## Case 1.
  echo -e "\nCase 1: Check group-aliases in the config have been added."

  sleep 2
  for group_aliases_id in $(group_aliases_ids); do
    vault read -format=json identity/group-alias/id/${group_aliases_id} | jq -r '.data.name' \
    | egrep "group_aliases_foo|group_aliases_bar"
  done
  test_case_passed

  #
  ## Case 2.
  echo -e "\nCase 2: Vault config removed when purgeUnmanagedConfig is enabled."

  # 2.1. Remove group-aliase from the config.
  yq -i 'del(.group-aliases[] | select(.name == "group_aliases_foo"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 2.2. Check the removed group-aliase is NOT in Vault.
  sleep 2
  for group_aliases_id in $(group_aliases_ids); do
    vault read -format=json identity/group-alias/id/${group_aliases_id} | jq -r '.data.name' \
    | (! grep "group_aliases_foo")
  done
  test_case_passed

  #
  ## Case 3.
  echo -e "\nCase 3: Vault config exists when the config excluded in purgeUnmanagedConfig."

  # 3.1. Disable purge for group-aliase.
  yq -i '.purgeUnmanagedConfig.exclude.group-aliases = true' "${bank_vaults_config_file}"

  # 3.2. Remove group-aliase from the config.
  yq -i 'del(.group-aliases[] | select(.name == "group_aliases_bar"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 3.3. Check the removed group is IN Vault.
  sleep 2
  for group_aliases_id in $(group_aliases_ids); do
    vault read -format=json identity/group-alias/id/${group_aliases_id} | jq -r '.data.name' \
    | grep "group_aliases_bar"
  done
  test_case_passed

  #
  ## Success.
  echo "All group-aliases test cases have been passed."
}


#
# Test group - StartupSecrets
#
startup_secrets_test () {
  # Note: The "startupSecrets" doesn't have purge option; hence, we only check the values.
  bank_vaults_config_copy "secrets startupSecrets"
  sleep 2

  #
  ## Case 1.
  echo -e "\nCase 1: Check startupSecrets in the config have been added."
  test "$(vault kv get -field=secret passwords/foo)" == "foo"; test_case_passed
  test "$(vault kv get -field=secret passwords/bar)" == "bar"; test_case_passed

  #
  ## Success.
  echo "All startupSecrets test cases have been passed."
}


#
# Test group - Secrets
#
secrets_test () {
  bank_vaults_config_copy "secrets"
  local get_vault_values_json='vault secrets list -format=json'

  #
  ## Case 1.
  echo -e "\nCase 1: Check secrets in the config have been added."

  test "$(${get_vault_values_json} | jq -r '."secret_foo/".type')" == "kv"; test_case_passed
  test "$(${get_vault_values_json} | jq -r '."secret_bar/".type')" == "ssh"; test_case_passed
  # If the "path" key is not defined, then the "type" value should be used as "path".
  test "$(${get_vault_values_json} | jq -r '."ssh/".type')" == "ssh"; test_case_passed

  #
  ## Case 2.
  echo -e "\nCase 2: Vault config removed when purgeUnmanagedConfig is enabled."

  # 2.1. Remove secret from the config.
  yq -i 'del(.secrets[] | select(.path == "secret_foo"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 2.2. Check the removed secret is NOT in Vault.
  test "$(${get_vault_values_json} | jq -r '."secret_foo/".type')" == "null"; test_case_passed

  #
  ## Case 3.
  echo -e "\nCase 3: Vault config exists when the config excluded in purgeUnmanagedConfig."

  # 3.1. Disable purge for secrets.
  yq -i '.purgeUnmanagedConfig.exclude.secrets = true' "${bank_vaults_config_file}"

  # 3.2. Remove secrets from the config.
  yq 'del(.secrets[] | select(.path == "secret_bar"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 3.3. Check the removed secrets is IN Vault.
  test "$(${get_vault_values_json} | jq -r '."secret_bar/".type')" == "ssh"; test_case_passed

  #
  ## Success.
  echo "All secrets test cases have been passed."
}


#
# Test group - Policies
#
policies_test () {
  bank_vaults_config_copy 'policies'
  local get_vault_values_json='vault policy list -format=json'

  #
  ## Case 1.
  echo -e "\nCase 1: Check policies in the config have been added."

  test "$(${get_vault_values_json} | jq -r '.[] | select(. == "policy_foo")')" == "policy_foo"; test_case_passed
  test "$(${get_vault_values_json} | jq -r '.[] | select(. == "policy_bar")')" == "policy_bar"; test_case_passed

  #
  ## Case 2.
  echo -e "\nCase 2: Vault config removed when purgeUnmanagedConfig is enabled."

  # 2.1. Remove policy from the config.
  yq -i 'del(.policies[] | select(.name == "policy_foo"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 2.2. Check the removed policy is NOT in Vault.
  test "$(${get_vault_values_json} | jq -r '.[] | select(. == "policy_foo")')" == ""; test_case_passed

  #
  ## Case 3.
  echo -e "\nCase 3: Vault config exists when the config excluded in purgeUnmanagedConfig."

  # 3.1. Disable purge for policy.
  yq -i '.purgeUnmanagedConfig.exclude.policies = true' "${bank_vaults_config_file}"

  # 3.2. Remove policy from the config.
  yq -i 'del(.policies[] | select(.name == "policy_bar"))' "${bank_vaults_config_file}"
  bank_vaults_config_touch

  # 3.3. Check the removed policy is IN Vault.
  test "$(${get_vault_values_json} | jq -r '.[] | select(. == "policy_bar")')" == "policy_bar"; test_case_passed

  #
  ## Success.
  echo "All polices test cases have been passed."
}

case ${bank_vaults_config_key} in
  "all")
    audit_test
    auth_test
    groups_test
    group_aliases_test
    policies_test
    startup_secrets_test
    secrets_test
    ;;

  "audit")
    audit_test
    ;;

  "auth")
    auth_test
    ;;

  "groups")
    groups_test
    ;;

  "group-aliases")
    group_aliases_test
    ;;

  "policies")
    policies_test
    ;;

  "startupSecrets")
    startup_secrets_test
    ;;

  "secrets")
    secrets_test
    ;;

  *)
    echo "This key is not supported."
    ;;
esac
