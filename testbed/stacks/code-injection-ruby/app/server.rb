require 'sinatra'
require 'json'
require 'base64'
require 'yaml'
require 'oj'

set :bind, '0.0.0.0'
set :port, 8080

get '/health' do
  'ok'
end

post '/eval' do
  input = params['input'] || ''
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    result = eval(input)
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: result.to_s, error: nil, time_ms: elapsed.round(2) }.to_json
  rescue => e
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: nil, error: e.to_s, time_ms: elapsed.round(2) }.to_json
  end
end

post '/system' do
  input = params['input'] || ''
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    result = `#{input}`
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: result.to_s, error: nil, time_ms: elapsed.round(2) }.to_json
  rescue => e
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: nil, error: e.to_s, time_ms: elapsed.round(2) }.to_json
  end
end

post '/backticks' do
  input = params['input'] || ''
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    result = %x(#{input})
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: result.to_s, error: nil, time_ms: elapsed.round(2) }.to_json
  rescue => e
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: nil, error: e.to_s, time_ms: elapsed.round(2) }.to_json
  end
end

post '/marshal' do
  input = params['input'] || ''
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    result = Marshal.load(Base64.decode64(input))
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: result.to_s, error: nil, time_ms: elapsed.round(2) }.to_json
  rescue => e
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: nil, error: e.to_s, time_ms: elapsed.round(2) }.to_json
  end
end

post '/oj' do
  input = params['input'] || ''
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    Oj.default_options = { mode: :object, class_cache: true }
    result = Oj.load(input)
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: result.to_s, error: nil, time_ms: elapsed.round(2) }.to_json
  rescue => e
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: nil, error: e.to_s, time_ms: elapsed.round(2) }.to_json
  end
end

post '/yaml' do
  input = params['input'] || ''
  # Convert literal \n to actual newlines (for single-line Burp Intruder payloads)
  input = input.gsub("\\n", "\n")
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    result = YAML.unsafe_load(input)
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: result.to_s, error: nil, time_ms: elapsed.round(2) }.to_json
  rescue => e
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
    content_type :json
    { output: nil, error: e.to_s, time_ms: elapsed.round(2) }.to_json
  end
end
