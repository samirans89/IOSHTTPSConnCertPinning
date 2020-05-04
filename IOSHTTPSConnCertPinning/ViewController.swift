//
//  ViewController.swift
//  IOSHTTPSConnCertPinning
//
//  Created by Samiran Saha on 03/05/20.
//  Copyright © 2020 Samiran Saha. All rights reserved.
//

import UIKit

var bundledSslCert = "invalid_cert"
var bundledSslCertExt = "der"


class ViewController: UIViewController {
    
    var localHTTPSEndpoint = "https://bs-local.com:4443"
    
    @IBOutlet weak var textViewServerData: UITextView!
    
    @IBOutlet weak var textLocalHostEndpoint: UITextField!
    
    @IBOutlet weak var textCertName: UITextField!

    
    @IBAction func processGoButtonClick(_ sender: Any) {
        
        bundledSslCert = textCertName.text!
        
        if let url = NSURL(string: textLocalHostEndpoint.text!) {
            let session = URLSession(
                configuration: URLSessionConfiguration.ephemeral,
                delegate: URLSessionPinningDelegate(),
                delegateQueue: nil)
            let task = session.dataTask(with: url as URL, completionHandler: { (data, response, error) -> Void in
                if error != nil {
                    DispatchQueue.main.async {
                        self.textViewServerData.text = error!.localizedDescription
                                                                  }
                    print("error: \(error!.localizedDescription)")
                } else if data != nil {
                    if let str = NSString(data: data!, encoding: String.Encoding.utf8.rawValue) {
                        print("Received data:\n\(str)")
                        DispatchQueue.main.async {
                            self.textViewServerData.text = str as String
                        }

                    }
                    else {
                        print("Unable to convert data to text")
                        DispatchQueue.main.async {
                                                   self.textViewServerData.text = "Unable to convert data to text"
                                               }
                    }
                }
            })
            
            task.resume()
        }
        else {
            print("Unable to create NSURL")
        }
        
        
    }
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
        textViewServerData.isScrollEnabled = false
        textLocalHostEndpoint.text = localHTTPSEndpoint
        textCertName.text = bundledSslCert
        
        processGoButtonClick(self);
        
    }
}


import Foundation
import Security
class URLSessionPinningDelegate: NSObject, URLSessionDelegate {
    

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Swift.Void) {
        if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                var secresult = SecTrustResultType.invalid
                let status = SecTrustEvaluate(serverTrust, &secresult)
                if(errSecSuccess == status) {
                    if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                        let serverCertificateData = SecCertificateCopyData(serverCertificate)
                        let data = CFDataGetBytePtr(serverCertificateData);
                        let size = CFDataGetLength(serverCertificateData);
                        let cert1 = NSData(bytes: data, length: size)
                        let file_der = Bundle.main.path(forResource: bundledSslCert, ofType: bundledSslCertExt)
                        
                        if let file = file_der {
                            if let cert2 = NSData(contentsOfFile: file) {
                                if cert1.isEqual(to: cert2 as Data) {
                                    completionHandler(URLSession.AuthChallengeDisposition.useCredential, URLCredential(trust:serverTrust))
                                    return
                                }
                            }
                        }
                    }
                }

            }
        }
        // Pinning failed
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}

