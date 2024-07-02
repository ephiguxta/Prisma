#!/usr/bin/env bash
#
# SubEnumr - Ferramenta de Recon diária para enumeração
# de subdomínios com base no subfinder e em wordlists públicas
#
# Uso: ./subEnumr <domain>
#
# > .<domain>.db é criado, sanitizado duplicados e atualizado
# com novos subdomains encontrados
# > <domain>.txt é criado e deve ser analisado como relatório

if [[ $# -eq 0  ]]; then
	echo "Usage $0 <domain>"
	exit 0
fi

DOMAIN="$1"
SAVE="$1.tmp"
FILES=("/home/$USER/Tools/subEnumr/big.txt" "/home/$USER/Tools/subEnumr/common-and-portuguese.txt")
LGT=$(echo ${#FILES[@]})

for ((i=0; i<$LGT; i++));
do
    if [ ! -f ${FILES[i]} ]; then
	echo "Arquivo ${FILES[$i]} não existe"
	exit 1
    fi
done 

subfinder -d $DOMAIN -nW -o $SAVE

for i in $(seq 0 2); do

    while read -r SUB; do
	HTTP="http://$SUB.$DOMAIN"
        HTTPS="https://$SUB.$DOMAIN"
	
	clear
	echo -e "Consultando: \033[0;32m$HTTP \033[0m"
	
	STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 40 "$HTTP")
        if [[ "$STATUS" -ne "404" && "$STATUS" -ne "000" ]]; then
                echo -e "[\033[0;32m$HTTP\033[0m] Status: $STATUS"
                echo "$SUB.$DOMAIN" >> "$SAVE"
		sleep 1
        fi
	
	clear
        echo -e "Consultando: \033[0;32m$HTTPS \033[0m"
	
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 40 "$HTTPS")
        if [[ "$STATUS" -ne "404" && "$STATUS" -ne "000" ]]; then
                echo -e "[\033[0;32m$HTTPS\033[0m] Status: $STATUS"
                echo "$SUB.$DOMAIN" >> "$SAVE"
		sleep 1
        fi
	
    done < ${FILES[$i]}

done

clear

DB=".$DOMAIN.db"
RELATORIO="$DOMAIN.txt"

if [ -f $DB ]; then
	DIFF=$(comm -3 <(sort $DB) <(sort $SAVE) | sed 's/\t//g' >> $DB)
	clear
        echo $DIFF
	uniq $SAVE | sed 's/\t//g' >> $RELATORIO
	rm $SAVE
    else
	    sort $SAVE | uniq | tee $DB $RELATORIO
	    rm $SAVE
	    clear
	    cat $RELATORIO

fi

echo ""
echo "FIM"







