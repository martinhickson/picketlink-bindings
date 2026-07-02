import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(private http: HttpClient) {}

  info(): Observable<unknown> {
    return this.http.get('../api/info');
  }

  metadataJson(): Observable<unknown> {
    return this.http.get('../api/admin/federation/metadata');
  }
}
