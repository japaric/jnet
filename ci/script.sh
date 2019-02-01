set -euxo pipefail

main() {
    if [ $TARGET = rustfmt ]; then
        cargo fmt -- --check
        return
    fi

    cargo check --target $TARGET

    if [ $TARGET = x86_64-unknown-linux-gnu ]; then
        cargo test -p owning-slice --target $TARGET
        cargo test -p owning-slice --target $TARGET --release

        cargo test --target $TARGET
        cargo test --target $TARGET --release

        pushd tools
        cargo check --target $TARGET --bins
        popd

        if [ $TRAVIS_RUST_VERSION = nightly ]; then
            export RUSTFLAGS="-Z sanitizer=address"
            # export ASAN_OPTIONS="detect_odr_violation=0"

            cargo test --target $TARGET --lib
            cargo test --target $TARGET --lib --release
        fi
    elif [ $TARGET = thumbv7m-none-eabi ]; then
        ( cd panic-never && cargo build --examples --release )

        if [ $TRAVIS_RUST_VERSION = nightly ]; then
            pushd firmware
            local examples=(
                hello
                ipv4
                ipv6
            )

            cargo build --target $TARGET --examples --release
            cd target/$TARGET/release/examples/
            size ${examples[@]}
            size -A ${examples[@]}
            popd
        fi
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
