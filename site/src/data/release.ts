import { REPO_URL, VERSION } from "@/lib/site";

export const RELEASE_DOWNLOAD = `${REPO_URL}/releases/download/${VERSION}`;
export const GO_MOD_URL = `${REPO_URL}/blob/${VERSION}/go.mod`;

// Direct dependencies, read from go.mod at v0.2.0 (unchanged since v0.1.0).
export const goDeps = [
  ["filippo.io/age", "v1.3.2", "encryption"],
  ["github.com/spf13/cobra", "v1.10.2", "CLI"],
  ["github.com/BurntSushi/toml", "v1.6.0", "config.toml"],
  ["github.com/zalando/go-keyring", "v0.2.8", "OS keyring"],
  ["golang.org/x/term", "v0.48.0", "hidden prompt"],
] as const;

// SHA-256 from checksums.txt of the v0.2.0 release.
export const checksums = [
  ["darwin_amd64.tar.gz", "c728128829dd9b00014d664fdd8e15ab8bd9c297cdabe92c8ef43e2a00bbccc2"],
  ["darwin_arm64.tar.gz", "7f557d91c3589b611e37f21a3e3c13ec52af9efbe5570650385b5b2ec2a2ed22"],
  ["linux_amd64.tar.gz", "7bba86798e7e3d1d849c66456a962b0c5df1c1022db01e517e730998903d7c01"],
  ["linux_arm64.tar.gz", "5df6ce2d7f03e5228a9984e819051dfde4a0428dce1f16436952d36d900de108"],
  ["windows_amd64.zip", "d7f055eef329f62cd52dc7c9ba67b3ae709302e74ac11a8c0f9a24980543007d"],
  ["windows_arm64.zip", "fc4e3db3168ee2a4a5c0de963ebbf1a3f067c63561fafeab0c7b123816e11f87"],
] as const;

export const verifyCode = `curl -fsSLO ${RELEASE_DOWNLOAD}/checksums.txt
curl -fsSLO ${RELEASE_DOWNLOAD}/keytwig_${VERSION.slice(1)}_linux_amd64.tar.gz
sha256sum -c checksums.txt --ignore-missing`;
