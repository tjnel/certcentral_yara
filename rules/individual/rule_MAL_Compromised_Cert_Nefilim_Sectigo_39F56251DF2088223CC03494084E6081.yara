import "pe"

rule MAL_Compromised_Cert_Nefilim_Sectigo_39F56251DF2088223CC03494084E6081 {
   meta:
      description         = "Detects Nefilim with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-03-06"
      version             = "1.0"

      hash                = "08c7dfde13ade4b13350ae290616d7c2f4a87cbeac9a3886e90a175ee40fb641"
      malware             = "Nefilim"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Inter Med Pty. Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "39:f5:62:51:df:20:88:22:3c:c0:34:94:08:4e:60:81"
      cert_thumbprint     = "29239659231A88CA518839BF57048FF79A272554"
      cert_valid_from     = "2020-03-06"
      cert_valid_to       = "2021-03-06"

      country             = "AU"
      state               = "Queensland"
      locality            = "North Lakes"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "39:f5:62:51:df:20:88:22:3c:c0:34:94:08:4e:60:81"
      )
}
