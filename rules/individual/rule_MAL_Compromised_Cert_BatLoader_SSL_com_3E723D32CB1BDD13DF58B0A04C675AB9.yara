import "pe"

rule MAL_Compromised_Cert_BatLoader_SSL_com_3E723D32CB1BDD13DF58B0A04C675AB9 {
   meta:
      description         = "Detects BatLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-11-21"
      version             = "1.0"

      hash                = "2e65cfebde138e4dd816d3e8b8105e796c4eb38cfa27015938c0445ee5be8331"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Agilable Consulting Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3e:72:3d:32:cb:1b:dd:13:df:58:b0:a0:4c:67:5a:b9"
      cert_thumbprint     = "F74DD023E63DDCCB72CF8BF70611EEAEC2DCD381"
      cert_valid_from     = "2022-11-21"
      cert_valid_to       = "2023-09-26"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "1006944-2"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3e:72:3d:32:cb:1b:dd:13:df:58:b0:a0:4c:67:5a:b9"
      )
}
