#! /usr/bin/env bash

set -eo pipefail

test ! -d secret -a -n "$SECRET_ZIP_PASS" && 7z -P"$SECRET_ZIP_PASS" x secret.7z

SOURCE=src/porridge.py
COMMON_FLAGS=(--onefile --hidden-import pkg_resources.py2_warn)

case "$BUILD_TYPE" in
    test)
        cp secret/config-test.py src/config.py
        ;;

    release)
        cp secret/config-release.py src/config.py
        ;;

    *)
        cp src/config-example.py src/config.py
        ;;
esac

case "$BUILD_OS" in
    windows*)
        pyinstaller --name mhroat --windowed "${COMMON_FLAGS[@]}" --hidden-import 'keyring.backends.Windows' --add-data 'mhroat.xrc;.' $SOURCE
        pyinstaller --name mhroatc --console "${COMMON_FLAGS[@]}" --hidden-import 'keyring.backends.Windows' --add-data 'mhroat.xrc;.' $SOURCE
        ;;

    macos*)
        pyinstaller --name MHROAT --windowed "${COMMON_FLAGS[@]}" --hidden-import 'keyring.backends.OS_X' --add-data 'mhroat.xrc:.' $SOURCE
        pushd dist
        zip -rm MHROAT.app.zip MHROAT.app
        rm MHROAT # Single executable not useful as it can't start the GUI
        popd
        ;;

    ubuntu*)
        pyinstaller --name mhroat --windowed "${COMMON_FLAGS[@]}" --hidden-import 'keyring.backends.SecretService' --add-data 'mhroat.xrc:.' $SOURCE
        ;;

    *)
        echo "BUILD_OS environment variable not set; set to windows, macos or ubuntu and retry"
        exit 1
esac
