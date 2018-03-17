set -euxo pipefail

main() {
    if [ $TARGET = x86_64-unknown-linux-gnu ]; then
        cargo check --target $TARGET
        cargo check --target $TARGET --examples
        return
    fi

    xargo check --target $TARGET
}

if [ $TRAVIS_BRANCH != master ]; then
    main
fi
