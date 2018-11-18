# National Vulnerability Database Notifier

Notifies on Slack when a new vulnerability is added to the https://nvd.nist.gov database.

* Runs as a Lambda every 30 minutes.
* Limit to relevant vendors and products by using include filters.
* Notify via Slack Webhook.


```go
func IncludeGo(cve nvd.CVEItem) (include bool) {
	for _, vd := range cve.CVE.Affects.Vendor.VendorData {
		if vd.VendorName != "golang" {
			continue
		}
		for _, pd := range vd.Product.ProductData {
			if pd.ProductName == "go" {
				return true
			}
		}
  }
  return false
}
  ```