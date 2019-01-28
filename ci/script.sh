set -euxo pipefail

main() {
    if [ $TARGET = rustfmt ]; then
        cargo fmt -- --check
        return
    fi

    cargo check --target $TARGET

    if [ $TARGET = x86_64-unknown-linux-gnu ]; then
        cargo check --target $TARGET --examples
        cargo test --target $TARGET
        return
    elif [ $TARGET = thumbv7m-none-eabi ] && [ $TRAVIS_RUST_VERSION = nightly ]; then
        ( cd panic-never && cargo build --examples --release )
    fi
}

# fake Travis variables to be able to run this on a local machine
if [ -z ${TRAVIS_BRANCH-} ]; then
    TRAVIS_BRANCH=auto
fi

if [ -z ${TRAVIS_RUST_VERSION-} ]; then
    case $(rustc -V) in
        *nightly*)
            TRAVIS_RUST_VERSION=nightly
            ;;
        *beta*)
            TRAVIS_RUST_VERSION=beta
            ;;
        *)
            TRAVIS_RUST_VERSION=stable
            ;;
    esac
fi

if [ -z ${TARGET-} ]; then
    TARGET=$(rustc -Vv | grep host | cut -d ' ' -f2)
fi

if [ $TRAVIS_BRANCH != master ] || [ $TRAVIS_PULL_REQUEST != false ]; then
    main
fi
