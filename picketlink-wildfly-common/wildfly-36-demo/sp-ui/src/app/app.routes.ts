import { Routes } from '@angular/router';
import { HomeComponent } from './home.component';
import { AdminComponent } from './admin.component';
import { SecuredComponent } from './secured.component';
import { authGuard } from './auth.guard';

export const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'admin', component: AdminComponent },
  { path: 'secured', component: SecuredComponent, canActivate: [authGuard] },
  { path: '**', redirectTo: '' }
];
