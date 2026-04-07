use Mojolicious::Lite -signatures;
use Time::HiRes qw(time);
use JSON::PP;
use Storable qw(thaw);
use MIME::Base64;
use YAML;

my $json = JSON::PP->new->utf8;

get '/health' => sub ($c) {
    $c->render(text => 'ok');
};

post '/eval' => sub ($c) {
    my $input = $c->param('input') // '';
    my $start = time();
    my $result = eval($input);
    my $elapsed = (time() - $start) * 1000;
    if ($@) {
        $c->render(json => { output => undef, error => "$@", time_ms => sprintf("%.2f", $elapsed) + 0 });
    } else {
        $c->render(json => { output => "$result", error => undef, time_ms => sprintf("%.2f", $elapsed) + 0 });
    }
};

post '/system' => sub ($c) {
    my $input = $c->param('input') // '';
    my $start = time();
    eval {
        my $result = `$input`;
        my $elapsed = (time() - $start) * 1000;
        $c->render(json => { output => "$result", error => undef, time_ms => sprintf("%.2f", $elapsed) + 0 });
    };
    if ($@) {
        my $elapsed = (time() - $start) * 1000;
        $c->render(json => { output => undef, error => "$@", time_ms => sprintf("%.2f", $elapsed) + 0 });
    }
};

post '/backticks' => sub ($c) {
    my $input = $c->param('input') // '';
    my $start = time();
    eval {
        my $result = qx($input);
        my $elapsed = (time() - $start) * 1000;
        $c->render(json => { output => "$result", error => undef, time_ms => sprintf("%.2f", $elapsed) + 0 });
    };
    if ($@) {
        my $elapsed = (time() - $start) * 1000;
        $c->render(json => { output => undef, error => "$@", time_ms => sprintf("%.2f", $elapsed) + 0 });
    }
};

post '/storable' => sub ($c) {
    my $input = $c->param('input') // '';
    my $start = time();
    eval {
        my $data = decode_base64($input);
        my $obj = thaw($data);
        my $elapsed = (time() - $start) * 1000;
        $c->render(json => { output => "$obj", error => undef, time_ms => sprintf("%.2f", $elapsed) + 0 });
    };
    if ($@) {
        my $elapsed = (time() - $start) * 1000;
        $c->render(json => { output => undef, error => "$@", time_ms => sprintf("%.2f", $elapsed) + 0 });
    }
};

post '/yaml' => sub ($c) {
    my $input = $c->param('input') // '';
    my $start = time();
    eval {
        my $obj = YAML::Load($input);
        my $elapsed = (time() - $start) * 1000;
        $c->render(json => { output => "$obj", error => undef, time_ms => sprintf("%.2f", $elapsed) + 0 });
    };
    if ($@) {
        my $elapsed = (time() - $start) * 1000;
        $c->render(json => { output => undef, error => "$@", time_ms => sprintf("%.2f", $elapsed) + 0 });
    }
};

app->start;
