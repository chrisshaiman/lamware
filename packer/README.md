# Packer builds

## Builder version

**Packer 1.16.0**, released 2026-07-24.

```
5edcd14ab59b535040c512dbecd6ec9ef976a000b073c19d93e4c431c948581e  packer_1.16.0_linux_amd64.zip
```

```sh
cd /tmp
curl -fsSLO https://releases.hashicorp.com/packer/1.16.0/packer_1.16.0_linux_amd64.zip
echo "5edcd14ab59b535040c512dbecd6ec9ef976a000b073c19d93e4c431c948581e  packer_1.16.0_linux_amd64.zip" \
  | sha256sum -c -          # STOP unless this prints OK
sudo unzip -o /tmp/packer_1.16.0_linux_amd64.zip -d /usr/local/bin
packer version
```

Verify the checksum as its own step. Chaining it into the unzip makes it easy to
miss a failure and install anyway.

Installed as a **pinned binary rather than from HashiCorp's apt repo**, which
tracks latest. The builder version is an input to the image — a different Packer
can produce a different guest — and an auto-updating repo is the same shape as
the floating `mcr.microsoft.com/dotnet/sdk:10.0` tag that left the dotnet image
unbuildable in #514.

Every `*.pkr.hcl` declares `required_version = "~> 1.16.0"`, so Packer itself
refuses a mismatched builder. Patch releases inside 1.16.x are allowed, so a
security fix is not blocked; a minor bump is a deliberate decision.

## Still not fully pinned: the qemu plugin

`packer init` fetches the `qemu` plugin from GitHub on first run. The constraint
is `~> 1.1`, so any 1.x release satisfies it.

**Packer has no plugin lockfile.** An earlier version of this file said to commit
a `.pkr.hcl.lock` after the first `packer init` — that is a Terraform concept and
does not exist in Packer. Verified: `packer init windows11-base.pkr.hcl` installs
the plugin and writes no lock file anywhere, with `required_plugins` correctly
declared.

So the constraint *is* the pin, and `~> 1.1` is too loose to reproduce a build.
What `packer init` actually installed is recorded under
`~/.config/packer/plugins/github.com/hashicorp/qemu/`, alongside a
`..._SHA256SUM` file:

```
packer-plugin-qemu_v1.1.6_x5.0_linux_amd64
packer-plugin-qemu_v1.1.6_x5.0_linux_amd64_SHA256SUM
```

To make the plugin reproducible, tighten the constraint to the exact version in
every template that declares it:

```hcl
required_plugins {
  qemu = {
    source  = "github.com/hashicorp/qemu"
    version = "1.1.6"
  }
}
```

## Prerequisites the Makefile does not install

| need | why |
|---|---|
| `mtools` | `make autounattend-floppy` uses `mformat`/`mcopy` |
| `unzip` | to unpack the Packer release |
| a Windows 11 ISO | `win11_iso_path` in `packer.auto.pkrvars.hcl` |
| `packer/packer.auto.pkrvars.hcl` | **not tracked**; `make win11-base` hard-fails without it. Needs `win11_iso_path` and `win11_iso_checksum` |
| `/dev/kvm` | the build runs a real VM |
| ~50 GB free | base image plus outputs |

`make packer-setup` does **not** install these — it belongs to the Ubuntu
`make image` path and only fetches an ansible-galaxy role and generates a build
password hash.

## Output goes somewhere safe

`windows11-guest` and `windows11-office` write to `packer/output-guest/` and
`packer/output-office/`. Neither touches `/var/lib/libvirt/images/` — copying
them into place is a separate, irreversible step. `win11-base` uses
`packer build -force`, which deletes its own output directory, not the live
images.

Times: base 45–90 min, guest ~5 min, office ~15 min. Run under tmux.
