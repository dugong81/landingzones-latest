environment=$1
rm $environment-*

echo "cleaning ${environment}"
startline=`sed -n "/$environment-start/=" terraform.tfvars`
endline=`sed -n "/$environment-end/=" terraform.tfvars`
sed -i "" "${startline},${endline}d" terraform.tfvars
echo "cleaned ${environment}"
