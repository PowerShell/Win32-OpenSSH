#	$OpenBSD: reexec.sh,v 1.11 2017/04/30 23:34:55 djm Exp $
#	Placed in the Public Domain.

tid="reexec tests"

SSHD_ORIG=$SSHD
SSHD_COPY=$OBJ/sshd

# Start a sshd and then delete it
start_sshd_copy ()
{
	cp $SSHD_ORIG $SSHD_COPY
	SSHD=$SSHD_COPY
	start_sshd
	SSHD=$SSHD_ORIG
}

# Do basic copy tests
copy_tests ()
{
	rm -f ${COPY}
	${SSH} -nq -F $OBJ/ssh_config somehost \
	    cat ${DATA} > ${COPY}
	if [ $? -ne 0 ]; then
		fail "ssh cat $DATA failed"
	fi
	cmp ${DATA} ${COPY}		|| fail "corrupted copy"
	rm -f ${COPY}
}

verbose "test config passing"

cp $OBJ/sshd_config $OBJ/sshd_config.orig
start_sshd
echo "InvalidXXX=no" >> $OBJ/sshd_config

copy_tests

stop_sshd

cp $OBJ/sshd_config.orig $OBJ/sshd_config

# cygwin can't fork a deleted binary
if [ "$os" != "cygwin" ]; then

verbose "test reexec fallback"

start_sshd_copy
rm -f $SSHD_COPY

copy_tests

stop_sshd

verbose "test reexec fallback without privsep"

cp $OBJ/sshd_config.orig $OBJ/sshd_config
echo "UsePrivilegeSeparation=no" >> $OBJ/sshd_config

start_sshd_copy
rm -f $SSHD_COPY

copy_tests

stop_sshd

fi
