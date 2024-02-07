using Microsoft.VisualStudio.TestTools.UnitTesting;
using HMACSerialiser.Base64Encoders;

namespace Base64EncoderTests
{
    [TestClass]
    public class Base64Tests
    {
        [TestMethod]
        public void SimpleTestData()
        {
            string data = "Hello, World!";
            string encoded = Base64Encoder.Encode(data);
            string decoded = Base64Encoder.DecodeToString(encoded);

            Assert.AreEqual("SGVsbG8sIFdvcmxkIQ", encoded);
            Assert.AreEqual(data, decoded);
        }

        [TestMethod]
        public void LoremIpsumData()
        {
            string data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam aliquet libero nunc, eu congue lacus dignissim at. Mauris porta nisi id nulla volutpat, nec porttitor dui commodo. Morbi accumsan nisi massa, a viverra justo mattis a. Sed et magna blandit, hendrerit est a, porttitor odio. Phasellus venenatis suscipit ligula, sit amet ultrices velit faucibus et. Proin eget elit vitae elit convallis varius. Cras enim arcu, luctus vel massa eget, efficitur elementum odio. Pellentesque vulputate non neque ac efficitur. Donec feugiat lorem sit amet libero fringilla iaculis. Quisque sed leo ipsum. Aenean eu sem nec purus dictum pharetra sit amet vel enim. Proin ligula urna, scelerisque a mauris quis, varius commodo mauris. Morbi sit amet sem non odio efficitur mattis a pharetra urna. Praesent eget ultrices nulla. Quisque quis tempor orci, nec auctor velit. Sed nec posuere dui, varius sodales elit.\r\n\r\nPellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vivamus luctus felis lobortis, tincidunt libero sit amet, blandit mi. Duis risus lacus, semper ut hendrerit at, porttitor sit amet ex. Ut auctor molestie interdum. Donec sed ornare lectus. Aenean in sollicitudin sem. Fusce lacus urna, fringilla et vestibulum non, congue vitae urna. Curabitur eget risus dui.\r\n\r\nPellentesque rhoncus non erat tempor elementum. Cras et sem vel massa tempus molestie. Praesent condimentum diam nec ex vehicula efficitur. Phasellus sit amet dui interdum, luctus purus non, imperdiet est. Ut efficitur rutrum lorem, quis aliquet tellus accumsan sed. Morbi eu massa urna. Cras id quam mauris. In in congue lacus, vitae vehicula libero.\r\n\r\nAliquam eget aliquet est. Pellentesque sed diam ac neque scelerisque placerat. Vivamus semper ut nulla vitae tincidunt. Mauris interdum pharetra magna id tempus. Fusce pharetra iaculis odio nec tristique. Mauris sem ipsum, pretium eu sapien sit amet, viverra tristique purus. Ut commodo accumsan nibh ac commodo. Mauris non hendrerit ex. Sed imperdiet leo metus, id gravida massa varius non. Cras vulputate id leo eget vehicula. Donec porttitor tempus ullamcorper. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae;\r\n\r\nSed sapien ante, rhoncus sit amet sagittis finibus, euismod eu elit. Sed turpis neque, dictum at posuere eget, feugiat nec nisl. Sed nec arcu tincidunt, tempus nisl sed, maximus massa. Phasellus bibendum sit amet nunc vitae bibendum. Mauris ac cursus augue. Etiam quis libero eros. Donec congue mauris est, eget sodales tellus finibus eget. Donec id tristique sapien. Donec viverra sollicitudin euismod. Ut condimentum tellus enim, vitae fringilla quam molestie nec. Quisque eget massa at orci efficitur congue at sit amet ligula. Proin nec lectus quis lectus viverra tempus. Quisque ornare, eros non feugiat mattis, ex nunc convallis odio, eu placerat est libero ut massa. Vestibulum tristique convallis tellus, hendrerit iaculis orci mollis sed.";

            string encoded = Base64Encoder.Encode(data);
            string decoded = Base64Encoder.DecodeToString(encoded);

            string expectedEncoded = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gTnVsbGFtIGFsaXF1ZXQgbGliZXJvIG51bmMsIGV1IGNvbmd1ZSBsYWN1cyBkaWduaXNzaW0gYXQuIE1hdXJpcyBwb3J0YSBuaXNpIGlkIG51bGxhIHZvbHV0cGF0LCBuZWMgcG9ydHRpdG9yIGR1aSBjb21tb2RvLiBNb3JiaSBhY2N1bXNhbiBuaXNpIG1hc3NhLCBhIHZpdmVycmEganVzdG8gbWF0dGlzIGEuIFNlZCBldCBtYWduYSBibGFuZGl0LCBoZW5kcmVyaXQgZXN0IGEsIHBvcnR0aXRvciBvZGlvLiBQaGFzZWxsdXMgdmVuZW5hdGlzIHN1c2NpcGl0IGxpZ3VsYSwgc2l0IGFtZXQgdWx0cmljZXMgdmVsaXQgZmF1Y2lidXMgZXQuIFByb2luIGVnZXQgZWxpdCB2aXRhZSBlbGl0IGNvbnZhbGxpcyB2YXJpdXMuIENyYXMgZW5pbSBhcmN1LCBsdWN0dXMgdmVsIG1hc3NhIGVnZXQsIGVmZmljaXR1ciBlbGVtZW50dW0gb2Rpby4gUGVsbGVudGVzcXVlIHZ1bHB1dGF0ZSBub24gbmVxdWUgYWMgZWZmaWNpdHVyLiBEb25lYyBmZXVnaWF0IGxvcmVtIHNpdCBhbWV0IGxpYmVybyBmcmluZ2lsbGEgaWFjdWxpcy4gUXVpc3F1ZSBzZWQgbGVvIGlwc3VtLiBBZW5lYW4gZXUgc2VtIG5lYyBwdXJ1cyBkaWN0dW0gcGhhcmV0cmEgc2l0IGFtZXQgdmVsIGVuaW0uIFByb2luIGxpZ3VsYSB1cm5hLCBzY2VsZXJpc3F1ZSBhIG1hdXJpcyBxdWlzLCB2YXJpdXMgY29tbW9kbyBtYXVyaXMuIE1vcmJpIHNpdCBhbWV0IHNlbSBub24gb2RpbyBlZmZpY2l0dXIgbWF0dGlzIGEgcGhhcmV0cmEgdXJuYS4gUHJhZXNlbnQgZWdldCB1bHRyaWNlcyBudWxsYS4gUXVpc3F1ZSBxdWlzIHRlbXBvciBvcmNpLCBuZWMgYXVjdG9yIHZlbGl0LiBTZWQgbmVjIHBvc3VlcmUgZHVpLCB2YXJpdXMgc29kYWxlcyBlbGl0Lg0KDQpQZWxsZW50ZXNxdWUgaGFiaXRhbnQgbW9yYmkgdHJpc3RpcXVlIHNlbmVjdHVzIGV0IG5ldHVzIGV0IG1hbGVzdWFkYSBmYW1lcyBhYyB0dXJwaXMgZWdlc3Rhcy4gVml2YW11cyBsdWN0dXMgZmVsaXMgbG9ib3J0aXMsIHRpbmNpZHVudCBsaWJlcm8gc2l0IGFtZXQsIGJsYW5kaXQgbWkuIER1aXMgcmlzdXMgbGFjdXMsIHNlbXBlciB1dCBoZW5kcmVyaXQgYXQsIHBvcnR0aXRvciBzaXQgYW1ldCBleC4gVXQgYXVjdG9yIG1vbGVzdGllIGludGVyZHVtLiBEb25lYyBzZWQgb3JuYXJlIGxlY3R1cy4gQWVuZWFuIGluIHNvbGxpY2l0dWRpbiBzZW0uIEZ1c2NlIGxhY3VzIHVybmEsIGZyaW5naWxsYSBldCB2ZXN0aWJ1bHVtIG5vbiwgY29uZ3VlIHZpdGFlIHVybmEuIEN1cmFiaXR1ciBlZ2V0IHJpc3VzIGR1aS4NCg0KUGVsbGVudGVzcXVlIHJob25jdXMgbm9uIGVyYXQgdGVtcG9yIGVsZW1lbnR1bS4gQ3JhcyBldCBzZW0gdmVsIG1hc3NhIHRlbXB1cyBtb2xlc3RpZS4gUHJhZXNlbnQgY29uZGltZW50dW0gZGlhbSBuZWMgZXggdmVoaWN1bGEgZWZmaWNpdHVyLiBQaGFzZWxsdXMgc2l0IGFtZXQgZHVpIGludGVyZHVtLCBsdWN0dXMgcHVydXMgbm9uLCBpbXBlcmRpZXQgZXN0LiBVdCBlZmZpY2l0dXIgcnV0cnVtIGxvcmVtLCBxdWlzIGFsaXF1ZXQgdGVsbHVzIGFjY3Vtc2FuIHNlZC4gTW9yYmkgZXUgbWFzc2EgdXJuYS4gQ3JhcyBpZCBxdWFtIG1hdXJpcy4gSW4gaW4gY29uZ3VlIGxhY3VzLCB2aXRhZSB2ZWhpY3VsYSBsaWJlcm8uDQoNCkFsaXF1YW0gZWdldCBhbGlxdWV0IGVzdC4gUGVsbGVudGVzcXVlIHNlZCBkaWFtIGFjIG5lcXVlIHNjZWxlcmlzcXVlIHBsYWNlcmF0LiBWaXZhbXVzIHNlbXBlciB1dCBudWxsYSB2aXRhZSB0aW5jaWR1bnQuIE1hdXJpcyBpbnRlcmR1bSBwaGFyZXRyYSBtYWduYSBpZCB0ZW1wdXMuIEZ1c2NlIHBoYXJldHJhIGlhY3VsaXMgb2RpbyBuZWMgdHJpc3RpcXVlLiBNYXVyaXMgc2VtIGlwc3VtLCBwcmV0aXVtIGV1IHNhcGllbiBzaXQgYW1ldCwgdml2ZXJyYSB0cmlzdGlxdWUgcHVydXMuIFV0IGNvbW1vZG8gYWNjdW1zYW4gbmliaCBhYyBjb21tb2RvLiBNYXVyaXMgbm9uIGhlbmRyZXJpdCBleC4gU2VkIGltcGVyZGlldCBsZW8gbWV0dXMsIGlkIGdyYXZpZGEgbWFzc2EgdmFyaXVzIG5vbi4gQ3JhcyB2dWxwdXRhdGUgaWQgbGVvIGVnZXQgdmVoaWN1bGEuIERvbmVjIHBvcnR0aXRvciB0ZW1wdXMgdWxsYW1jb3JwZXIuIFZlc3RpYnVsdW0gYW50ZSBpcHN1bSBwcmltaXMgaW4gZmF1Y2lidXMgb3JjaSBsdWN0dXMgZXQgdWx0cmljZXMgcG9zdWVyZSBjdWJpbGlhIGN1cmFlOw0KDQpTZWQgc2FwaWVuIGFudGUsIHJob25jdXMgc2l0IGFtZXQgc2FnaXR0aXMgZmluaWJ1cywgZXVpc21vZCBldSBlbGl0LiBTZWQgdHVycGlzIG5lcXVlLCBkaWN0dW0gYXQgcG9zdWVyZSBlZ2V0LCBmZXVnaWF0IG5lYyBuaXNsLiBTZWQgbmVjIGFyY3UgdGluY2lkdW50LCB0ZW1wdXMgbmlzbCBzZWQsIG1heGltdXMgbWFzc2EuIFBoYXNlbGx1cyBiaWJlbmR1bSBzaXQgYW1ldCBudW5jIHZpdGFlIGJpYmVuZHVtLiBNYXVyaXMgYWMgY3Vyc3VzIGF1Z3VlLiBFdGlhbSBxdWlzIGxpYmVybyBlcm9zLiBEb25lYyBjb25ndWUgbWF1cmlzIGVzdCwgZWdldCBzb2RhbGVzIHRlbGx1cyBmaW5pYnVzIGVnZXQuIERvbmVjIGlkIHRyaXN0aXF1ZSBzYXBpZW4uIERvbmVjIHZpdmVycmEgc29sbGljaXR1ZGluIGV1aXNtb2QuIFV0IGNvbmRpbWVudHVtIHRlbGx1cyBlbmltLCB2aXRhZSBmcmluZ2lsbGEgcXVhbSBtb2xlc3RpZSBuZWMuIFF1aXNxdWUgZWdldCBtYXNzYSBhdCBvcmNpIGVmZmljaXR1ciBjb25ndWUgYXQgc2l0IGFtZXQgbGlndWxhLiBQcm9pbiBuZWMgbGVjdHVzIHF1aXMgbGVjdHVzIHZpdmVycmEgdGVtcHVzLiBRdWlzcXVlIG9ybmFyZSwgZXJvcyBub24gZmV1Z2lhdCBtYXR0aXMsIGV4IG51bmMgY29udmFsbGlzIG9kaW8sIGV1IHBsYWNlcmF0IGVzdCBsaWJlcm8gdXQgbWFzc2EuIFZlc3RpYnVsdW0gdHJpc3RpcXVlIGNvbnZhbGxpcyB0ZWxsdXMsIGhlbmRyZXJpdCBpYWN1bGlzIG9yY2kgbW9sbGlzIHNlZC4";
            Assert.AreEqual(expectedEncoded, encoded);
            Assert.AreEqual(data, decoded);
        }
    }
}
