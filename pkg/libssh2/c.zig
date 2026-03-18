const c = @cImport({
    @cInclude("libssh2.h");
    @cInclude("libssh2_sftp.h");
});
