import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { certificate } from './certificate.model';

@Injectable({
  providedIn: 'root'
})

export class CertificateService {

  constructor(private http: HttpClient) {

  }

  CA_SERVER = "http://192.168.2.22:5000"


  getCertificates(): Observable<certificate[]> {
    return this.http.get<certificate[]>(`${this.CA_SERVER}/get_certificate`)
  }
}
