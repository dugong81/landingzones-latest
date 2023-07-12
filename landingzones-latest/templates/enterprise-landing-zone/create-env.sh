environment=$1
prefix=$2
cp -R new-env $environment
for FILE in $environment/*;
do
    echo "$FILE";
	sed -i "" "s/newenv/$environment/g" $FILE;
	sed -i "" "s/environmentprefix/$prefix/g" $FILE;
	mv $FILE "$environment/$environment-`basename ${FILE%%.*}`.tf";
done
cp $environment/*.* .

cp new-vars/env.tfvars $environment
sed -i "" "s/newenv/$environment/g" $environment/env.tfvars;
sed -i "" "s/environmentprefix/$prefix/g" $environment/env.tfvars;
cat $environment/env.tfvars >> terraform.tfvars

rm -rf $environment
