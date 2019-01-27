set -euxo pipefail

main() {
    if [ $TARGET != rustfmt ]; then
        rustup target add $TARGET
    fi
}

main
