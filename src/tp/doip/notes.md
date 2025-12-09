# Onboarding Notes

## Install bazel

Project requires `bazel` 8.1.1 which can be installed via

```bash
sudo apt update && sudo apt install bazel-8.1.1
```

If version is not supported, `bazel` must be fetched from a different location, see [Bazel Home](https://bazel.build/install/ubuntu#install-on-ubuntu)

```bash
sudo apt install apt-transport-https curl gnupg -y
curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg
sudo mv bazel-archive-keyring.gpg /usr/share/keyrings
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list
```

## Install required tools

Install required Python modules

```bash
pip3 install -r requirements.txt
```

For the build this is not sufficient - you need to install also `codechecker`

```bash
pip3 install codechecker
```

Then you should be able to run `make` in the root dir

```bash
make
```
