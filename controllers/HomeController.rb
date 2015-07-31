class HomeController < ApplicationController
	get '/' do
		erb :index, :locals => {'body_class' => 'home'}
	end

	get '/not_authenticated' do
    erb :not_authenticated, :locals => {'body_class' => 'home'}
  end
end