import { CertificateService } from './../services/certificate.service';
import { certificate } from './../services/certificate.model';
import { Component } from '@angular/core';
import { Router } from '@angular/router';

@Component({
    selector: 'app-login',
    templateUrl: './login.component.html',
    styleUrls: ['./login.component.css']
})
export class LoginComponent {
    public passwordLogin: boolean = true;
    public username: string;
    public password: string;

    constructor(private CertificateServiceApi: CertificateService) {
    }

    certificate: certificate[];
    onSubmit() {
      {
        this.CertificateServiceApi.getCertificates().subscribe((certificate: certificate[]) => {
          this.certificate = certificate;
        })
        console.log(this.certificate);
        /*if (this.passwordLogin) {
            this.loginService.passwordLogin(this.username, this.password)
                .subscribe(
                    () => {
                        this.router.navigate(['/']);
                    },
                    (error: CAApiError) => {
                        this.error = error.message;
                    }
                )
        } else {
            this.loginService.certificateLogin()
                .subscribe(
                    () => {
                        this.router.navigate(['/']);
                    },
                    (error: CAApiError) => {
                        this.error = 'Could not login!';
                    }
                )
        }*/
        console.log("submit");
      }
    }
}
