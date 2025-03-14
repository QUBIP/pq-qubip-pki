document.addEventListener("DOMContentLoaded", function () {
    console.log("Certificate Details page loaded");

    const crlDistrPoint = document.getElementById("crlDistrPoint");
    if (crlDistrPoint) {
        crlDistrPoint.addEventListener("click", function () {
            console.log("CRL Distribution Point clicked");
            const ca = this.getAttribute("data-ca");
            const ca_crl = this.getAttribute("data-crl");
            console.log(ca);
            // Redirect to fetch CRL details recursively
            window.location.href = `/download_crl/${ca}/${ca_crl}`;
        });
    }

    // Handle "View CA Certificate" button click
    const viewCaCertBtn = document.getElementById("view-ca");
    if (viewCaCertBtn) {
        viewCaCertBtn.addEventListener("click", function () {
            console.log("View CA Certificate button clicked");
            const ca = this.getAttribute("data-ca");

            // Redirect to fetch CA certificate details recursively
            window.location.href = `/certificate_details/${ca}/ca_certificate`;
        });
    }
    else {
        console.log("ERRORE")
    }
    const downloadCert = document.getElementById("download-cert-link");
    if (downloadCert) {
        downloadCert.addEventListener("click", function () {
            const ca = this.getAttribute("data-ca");
            const cert_id = this.getAttribute("data-cert-id");

            // Fetch the CA certificate from the API
            fetch(`/download_certificate/${ca}/${cert_id}`, { method: 'GET' })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to download certificate');
                }
                return response.blob();
            })
            .then(blob => {
                const link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = `${cert_id}.zip`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            })
            .catch(error => {
                console.error("Error downloading CA certificate:", error);
            });
        });
    } else {
        console.log("Download CA button not found in DOM!");
    }
    // Attach event listeners to both the "Download Root CA certificate" button and the AIA link
    const downloadButton = document.getElementById("root-ca");  // The button
    const aiaLink = document.getElementById("aiaLink");  // The AIA link
    if (downloadButton) {
        downloadButton.addEventListener("click", handleDownloadCARequest);
    } else {
        console.log("Download Root CA Certificate button not found!");
    }
    
    if (aiaLink) {
        aiaLink.addEventListener("click", handleDownloadCARequest);
    } else {
        console.log("AIA Link not found!");
    }

    if (caButton) {
        caButton.addEventListener("click", function () {
            console.log("Download CA button clicked");
            const ca = this.getAttribute("data-ca");

            // Fetch the CA certificate from the API
            fetch(`/${ca}/download_ca_certificate/`, { method: 'GET' })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to download CA certificate');
                }
                return response.blob();
            })
            .then(blob => {
                console.log("CA certificate file received", blob);
                const link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = `${ca}-cert.pem`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            })
            .catch(error => {
                console.error("Error downloading CA certificate:", error);
            });
        });
    } else {
        console.log("Download CA button not found in DOM!");
    }

    const chainButton = document.getElementById("download-chain-link");
    console.log("Button found:", chainButton);

    if (chainButton) {
        chainButton.addEventListener("click", function () {
            const ca = this.getAttribute("data-ca");
            const cert_id=this.getAttribute("data-cert-id");

            // Fetch the CA certificate from the API
            fetch(`/${ca}/download_chain/${cert_id}`, { method: 'GET' })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to download chain');
                }
                return response.blob();
            })
            .then(blob => {
                console.log("certificate chain file received", blob);
                const link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = `${cert_id}-chain.pem`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            })
            .catch(error => {
                console.error("Error downloading chain:", error);
            });
        });
    } else {
        console.log("Download chain button not found in DOM!");
    }
});

function handleDownloadCARequest(event) {
    console.log("Download CA button/link clicked");
    const ca = this.getAttribute("data-ca");  // Get the value of 'data-ca'

    // Fetch the CA certificate from the API
    fetch(`/${ca}/download_ca_certificate/`, { method: 'GET' })
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to download CA certificate');
        }
        return response.blob();
    })
    .then(blob => {
        console.log("CA certificate file received", blob);
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${ca}-cert.pem`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    })
    .catch(error => {
        console.error("Error downloading CA certificate:", error);
    });
}
