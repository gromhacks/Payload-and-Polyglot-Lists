require 'sinatra'
require 'erb'
require 'slim'
require 'haml'
require 'json'

set :bind, '0.0.0.0'
set :port, 8080

get '/health' do
  'ok'
end

post '/erb' do
  input = params['input'] || ''
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    output = ERB.new(input).result(binding)
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: output, error: nil, time_ms: elapsed.round(2) }.to_json
  rescue => e
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: nil, error: e.to_s, time_ms: elapsed.round(2) }.to_json
  end
end

post '/slim' do
  input = params['input'] || ''
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    output = Slim::Template.new { input }.render
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: output, error: nil, time_ms: elapsed.round(2) }.to_json
  rescue => e
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: nil, error: e.to_s, time_ms: elapsed.round(2) }.to_json
  end
end

post '/haml' do
  input = params['input'] || ''
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    output = Haml::Engine.new(input).render
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: output, error: nil, time_ms: elapsed.round(2) }.to_json
  rescue => e
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: nil, error: e.to_s, time_ms: elapsed.round(2) }.to_json
  end
end
