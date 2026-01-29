#!/usr/bin/env zsh

function gw_build_images {
 pushd $PVXS/example/kubernetes/docker
 builder="./build.sh"

 if [[ "$1" == "gateway" || "$1" == "lab" ||  "$1" == "lab_base" || "$1" == "pvacms" ||  "$1" == "testioc" || "$1" == "tstioc" ]] ; then
  cd $1
  builder="./build_docker.sh"
  shift
 fi
 $builder $*
 popd
}

function gw_deploy {
 pushd $PVXS/example/kubernetes/helm
 if [[ "$1" == "-r" ]] ; then
  helm uninstall pvxs-lab -n pvxs-lab
  sleep 5
 fi
 helm upgrade --install pvxs-lab pvxs-lab -n pvxs-lab \
  --set gateway.expose.mode=NodePort \
  --set gateway.expose.enableUdp=false
 popd
}

function gw_undeploy {
  helm uninstall pvxs-lab -n pvxs-lab
}

function gw_internet_config {
 unset EPICS_PVA_INTF_ADDR_LIST
 unset EPICS_PVA_TLS_KEYCHAIN
 export EPICS_PVA_AUTO_ADDR_LIST=NO
 export EPICS_PVA_ADDR_LIST=""
 export EPICS_PVA_NAME_SERVERS="127.0.0.1:31075"
 echo "INTERNET mode: PVA client->${EPICS_PVA_NAME_SERVERS} ; ~/.config/pva/1.4/client.p12"
}

function go_in_to {
 if [[ "$1" == "lab" ||  "$1" == "pvacms" ||  "$1" == "testioc" || "$1" == "tstioc" || "$1" == "gateway" ]] ; then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-$1 -- /bin/bash
 else
  echo "No such lab system: $1"
  false
 fi
}

function login_to_lab {
 if [[ "$1" == "guest" || "$1" == "operator" ]] ; then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-lab -- su - $1
 elif [[ "$1" == "admin" || "$1" == "pvacms" ]] ;  then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-pvacms -- su - $1
 elif [[ "$1" == "testioc" ]] ; then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-testioc -- su - $1
 elif [[ "$1" == "tstioc" ]] ; then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-tstioc -- su - $1
 elif [[ "$1" == "gateway" ]] ; then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-gateway -- su - $1
 else
  echo "No such lab user: $1"
  false
 fi
}

function gw_cp {
  emulate -L zsh
  setopt local_options

  if (( $# < 3 || $# > 4 )); then
    echo "usage: gw_cp <sys> <user> <src> [dest]"
    echo "You gave $#"
    return 1
  fi

  local sys=$1
  local user=$2
  local src=$3
  local dst=${4:-./${src:t}}

  case "${sys}:${user}" in
    (gateway:gateway|pvacms:pvacms|testioc:testioc|tstioc:tstioc|pvacms:admin|lab:guest|lab:operator)
      ;;
    (*)
      echo "usage: gw_cp <sys> <user> <src> [dest]"
      echo "sys: gateway|pvacms|testioc|tstioc|lab"
      echo "user: gateway|pvacms|testioc|tstioc|admin|guest|operator"
      return 1
      ;;
  esac

  local POD
  POD=$(kubectl -n pvxs-lab get pod -l "app=$sys" -o jsonpath='{.items[0].metadata.name}') || return 1

  kubectl -n pvxs-lab exec -i "$POD" -- bash -lc \
    'su - "$1" -c "cat -- \"$2\""' _ "$user" "$src" > "$dst"
}

function gw_cp_in {
  emulate -L zsh
  setopt local_options

  if (( $# < 3 || $# > 4 )); then
    echo "usage: gw_cp <sys> <user> <src> [dest]"
    echo "You gave $#"
    return 1
  fi

  local sys=$1
  local user=$2
  local src=$3
  local dst=$4

  case "${sys}:${user}" in
    (gateway:gateway|pvacms:pvacms|testioc:testioc|tstioc:tstioc|pvacms:admin|lab:guest|lab:operator)
      ;;
    (*)
      echo "usage: gw_cp <sys> <user> <src> [dest]"
      echo "sys: gateway|pvacms|testioc|tstioc|lab"
      echo "user: gateway|pvacms|testioc|tstioc|admin|guest|operator"
      return 1
      ;;
  esac

  local POD
  POD=$(kubectl -n pvxs-lab get pod -l "app=$sys" -o jsonpath='{.items[0].metadata.name}') || return 1

  kubectl -n pvxs-lab cp $src "$POD:$dst"
}

function gw_log {
 if [[ "$1" == "lab" ||  "$1" == "pvacms" ||  "$1" == "testioc" || "$1" == "tstioc" || "$1" == "gateway" ]] ; then
  kubectl logs -n pvxs-lab deployment/pvxs-lab-$1  -f
 else
  echo "No such lab system: $1"
  false
 fi
}
