#!/bin/sh
set -e -x
# I (sometimes) inject environment

if [ "$TRAVIS_OS_NAME" = "windows" ]
then
    # travis sets these to gcc/g++
    unset CC
    unset CXX
    export TRAVIS_COMPILER=cl

    if [ ! -d "$HOME/tools" ]
    then
        echo "Available MSVC versions"
        find "/c/Program Files (x86)/Microsoft Visual Studio"* -name vcvars*.bat

        # it would be soooo nice if this worked...
        # but instead "Can't locate ExtUtils/Command.pm ..."
        #choco install make
        #choco install strawberryperl
        #choco list --local-only

        mkdir "$HOME/tools"

        curl -fsS --retry 3 -o "$HOME/tools"/make.zip https://epics.anl.gov/download/tools/make-4.2.1-win64.zip
        curl -fsS --retry 3 -o "$HOME/tools"/perl.zip http://strawberryperl.com/download/5.30.0.1/strawberry-perl-5.30.0.1-64bit.zip
        (cd "$HOME/tools" && unzip make.zip) >/dev/null
        (cd "$HOME/tools" && unzip perl.zip) >/dev/null

        cat <<EOF > msboot.bat
        cd %1
        call relocation.pl.bat
EOF
        ./msboot.bat "$HOME/tools" >/dev/null
    fi

    export PATH="$HOME/tools:$HOME/tools/perl/site/bin:$HOME/tools/perl/bin:$PATH"

    type make
    make --version
    type perl
    perl --version

    cat <<EOF > msboot.bat
echo Before PATH=%PATH%
where sh
:: pick up choco installs
::call RefreshEnv.cmd
:: which unfortunately removes /bin
::PATH=C:\program files\git\usr\bin;%PATH%

:: pull in MSVC
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86
echo After PATH=%PATH%

where cl
where perl
where sh
where make

sh "$@"
EOF

    ./msboot.bat
else
    sh "$@"
fi
