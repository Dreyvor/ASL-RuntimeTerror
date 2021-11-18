import { LoginComponent } from './login/login.component';
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

const routes: Routes = [
{ path: 'login', component: LoginComponent },
/*{ path: 'dashboard', component: DashboardComponent, canActivate: [AuthguardGuard] },
{
  path: 'registration-requests', component: RegistrationRequestsComponent, canActivate: [AuthguardGuard],
  data: {
    role: ['ROLE_ADMIN', 'ROLE_MANAGER', 'ROLE_USER']
  }
},*/
{ path: '**', redirectTo: 'login'},];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
