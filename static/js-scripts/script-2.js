document.addEventListener("DOMContentLoaded", function () {

    // Handle "Download CA Certificate" buttons
    document.querySelectorAll(".download-ca-cert-btn").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            const chainName = this.getAttribute("chain-name");
            const certName = this.getAttribute("cert-name");
            ////console.log(`Downloading certificate: ${certName}`);
            window.location.href = `/${chainName}/${certName}/certificate`;
        });
    });

    // Handle "View CA Certificate" buttons
    document.querySelectorAll(".view-ca-cert-btn").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            ////console.log("view ca cert button clicked");
            const chainName = this.getAttribute("chain-name");
            const certName = this.getAttribute("cert-name");
            ////console.log(`Viewing certificate: ${certName}`);
            window.location.href = `/certificate_details/${chainName}/${certName}/ca_certificate`;
        });
    });

    // Handle "Download CA CRL" buttons
    document.querySelectorAll(".download-crl-btn").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            const chainName = this.getAttribute("chain-name");
            const crlName = this.getAttribute("crl-name");
            ////console.log(`Downloading CRL: ${crlName}`);
            window.location.href = `/download_crl/${chainName}/${crlName}`;
        });
    });

    // Handle "View CA CRL" buttons
    document.querySelectorAll(".view-crl-btn").forEach(button => {
        button.addEventListener("click", function () {
            const chainName = this.getAttribute("chain-name");
            //console.log(chainName)
            const crlName = this.getAttribute("crl-name");
            ////console.log(`Viewing CRL: ${crlName}`);
            window.location.href = `/crl_details/${chainName}/${crlName}`;
        });
    });
});
