import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_Sectigo_6F3442C728DC9E9D63EB5F1EEC64C197 {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-04"
      version             = "1.0"

      hash                = "cfa3aa39deeb3f6676492660c22c6e47429f8dc19b39310c526528e960aa5541"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "KusderQounm Venitnet Futurkresl Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "6f:34:42:c7:28:dc:9e:9d:63:eb:5f:1e:ec:64:c1:97"
      cert_thumbprint     = "B52DDB58C551AFEE980F6ADD8F8162BC4E65F837"
      cert_valid_from     = "2024-03-04"
      cert_valid_to       = "2025-03-04"

      country             = "CN"
      state               = "福建省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350205MA356BHE2L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "6f:34:42:c7:28:dc:9e:9d:63:eb:5f:1e:ec:64:c1:97"
      )
}
