#!/bin/bash
#set -x

if [ $(id -u) -ne 0 ]
 then echo "Favor executar como root"
exit
fi

mkdir -p /root/backup/transparent_hugepage/

if [ -e /sys/kernel/mm/transparent_hugepage/enabled ]
 then
    echo ============================================================================
    echo "arquivo /sys/kernel/mm/transparent_hugepage/enabled encontrado com sucesso"
    echo "efetuando backup do arquivo enable"
    echo ============================================================================
        cp /sys/kernel/mm/transparent_hugepage/enabled /root/backup/transparent_hugepage/enabled.bkp >> /dev/null
    echo ""
    echo "alterando arquivo para never"
    echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled
    echo ""
else
    echo ============================================================================
    echo                         "arquivo nao encontrado"
    echo ============================================================================
fi

if [ -e /sys/kernel/mm/transparent_hugepage/defrag ]
then
    echo ============================================================================
    echo "arquivo /sys/kernel/mm/transparent_hugepage/defrag encontrado com sucesso"
    echo           "efetuando backup dos arquivos enable"
    echo ============================================================================
        sleep 3
        cp /sys/kernel/mm/transparent_hugepage/defrag /root/backup/transparent_hugepage/defrag.bkp >> /dev/null
    echo ""
    echo "alterando arquivo para never"
    echo ""
    echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag
else
    echo ============================================================================
    echo                         "arquivo nao encontrado"
    echo ============================================================================
fi

if [ -e /sys/kernel/mm/transparent_hugepage/enabled ]
 then
echo "verificar status enable"
    cat /sys/kernel/mm/transparent_hugepage/enabled
else
  echo "" >> /dev/null
fi
echo ""

if [ -e /sys/kernel/mm/transparent_hugepage/defrag ]
then
echo "verificar status defrag"
  cat /sys/kernel/mm/transparent_hugepage/defrag
else
echo "" >> /dev/null
fi
echo ""

if [ -e /sys/kernel/mm/redhat_transparent_hugepage/enabled ]
 then
echo "verificar status enable"
    cat /sys/kernel/mm/redhat_transparent_hugepage/enabled
else
echo "" >> /dev/null
fi
echo ""
if [ -e /sys/kernel/mm/redhat_transparent_hugepage/defrag ]
 then
echo "verificar status defrag"
    cat /sys/kernel/mm/redhat_transparent_hugepage/defrag
else
echo "" >> /dev/null
fi
echo "Saida do arquivo deverá ser always madvise [never]"
echo ""