document.addEventListener("DOMContentLoaded", function () {

    // Handle "Download CA Certificate" buttons
    document.querySelectorAll(".download-ca-cert-btn").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            const certName = this.getAttribute("cert-name");
            console.log(`Downloading certificate: ${certName}`);
            window.location.href = `/v2/certs/${certName}/certificate`;
        });
    });

    // Handle "View CA Certificate" buttons
    document.querySelectorAll(".view-ca-cert-btn").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            ////console.log("view ca cert button clicked");
            const certName = this.getAttribute("cert-name");
            ////console.log(`Viewing certificate: ${certName}`);
            window.location.href = `/v2/certificate_details/${certName}/ca_certificate`;
        });
    });

    // Handle "Download CA CRL" buttons
    document.querySelectorAll(".download-crl-btn").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            const crlName = this.getAttribute("crl-name");
            window.location.href = `/v2/certs/${crlName}/crl`;
        });
    });

    // Handle "View CA CRL" buttons
    document.querySelectorAll(".view-crl-btn").forEach(button => {
        button.addEventListener("click", function () {
            const crlName = this.getAttribute("crl-name");
            ////console.log(`Viewing CRL: ${crlName}`);
            window.location.href = `/v2/crl_details/v2/${crlName}`;
        });
    });
});
