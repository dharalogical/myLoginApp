Rails.application.routes.draw do
  root to: "home#index"
  get '/auth/google_oauth2/callback', to: 'sessions#google_auth'
  devise_for :users, controllers: { omniauth_callbacks: 'users/omniauth_callbacks' }
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html    

  # Defines the root path route ("/")
end
