"""
Commonly impersonated brands and the domains they really send from or link to.

tokens: strings that, when they show up in a domain, suggest the brand.
        Tokens of 6+ characters also match at the start of a label
        ("paypalsecure"); shorter ones must be a whole label or a part
        between hyphens ("ups-delivery"), to avoid hits like "groups".
display: words that suggest the brand in a From display name. Left empty
         for brands that are also common first names (e.g. Chase).
domains: organizational domains the brand really uses.
"""

BRANDS = {
    "PayPal": {
        "tokens": ["paypal"], "display": ["paypal"],
        "domains": ["paypal.com", "paypal.me"],
    },
    "Microsoft": {
        "tokens": ["microsoft", "office365", "onedrive", "sharepoint"],
        "display": ["microsoft", "office 365", "office365", "onedrive", "sharepoint", "outlook team"],
        "domains": ["microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "hotmail.com",
                    "microsoftonline.com", "sharepoint.com", "onedrive.com", "azure.com", "windows.com"],
    },
    "Apple": {
        "tokens": ["apple", "icloud"], "display": ["apple", "icloud", "itunes"],
        "domains": ["apple.com", "icloud.com", "me.com", "mac.com"],
    },
    "Amazon": {
        "tokens": ["amazon"], "display": ["amazon"],
        "domains": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.fr", "amazon.it", "amazon.es",
                    "amazon.co.jp", "amazon.in", "amazon.com.au", "amazon.com.mx", "amazon.com.br",
                    "amazonaws.com", "amazonses.com", "a2z.com"],
    },
    "Google": {
        "tokens": ["google", "gmail"], "display": ["google", "gmail"],
        "domains": ["google.com", "gmail.com", "googlemail.com", "youtube.com", "googleapis.com",
                    "googleusercontent.com", "gstatic.com", "withgoogle.com", "google.co.uk"],
    },
    "Netflix": {"tokens": ["netflix"], "display": ["netflix"], "domains": ["netflix.com"]},
    "DocuSign": {"tokens": ["docusign"], "display": ["docusign"], "domains": ["docusign.com", "docusign.net"]},
    "DHL": {"tokens": ["dhl"], "display": ["dhl"], "domains": ["dhl.com", "dhl.de"]},
    "FedEx": {"tokens": ["fedex"], "display": ["fedex"], "domains": ["fedex.com"]},
    "UPS": {"tokens": ["ups"], "display": [], "domains": ["ups.com"]},
    "USPS": {"tokens": ["usps"], "display": ["usps", "postal service"], "domains": ["usps.com", "usps.gov"]},
    "IRS": {"tokens": ["irs"], "display": ["irs", "internal revenue"], "domains": ["irs.gov"]},
    "Chase": {"tokens": ["chase"], "display": [], "domains": ["chase.com", "jpmorgan.com", "jpmorganchase.com"]},
    "Bank of America": {
        "tokens": ["bankofamerica"], "display": ["bank of america"], "domains": ["bankofamerica.com"],
    },
    "Wells Fargo": {"tokens": ["wellsfargo"], "display": ["wells fargo"], "domains": ["wellsfargo.com"]},
    "Coinbase": {"tokens": ["coinbase"], "display": ["coinbase"], "domains": ["coinbase.com"]},
    "Facebook": {
        "tokens": ["facebook", "instagram"], "display": ["facebook", "instagram"],
        "domains": ["facebook.com", "facebookmail.com", "instagram.com", "meta.com", "fb.com"],
    },
    "LinkedIn": {"tokens": ["linkedin"], "display": ["linkedin"], "domains": ["linkedin.com"]},
    "Dropbox": {"tokens": ["dropbox"], "display": ["dropbox"], "domains": ["dropbox.com", "dropboxmail.com"]},
    "Adobe": {"tokens": ["adobe"], "display": ["adobe"], "domains": ["adobe.com", "adobesign.com"]},
    "Norton": {"tokens": ["norton"], "display": ["norton"], "domains": ["norton.com"]},
    "McAfee": {"tokens": ["mcafee"], "display": ["mcafee"], "domains": ["mcafee.com"]},
}
