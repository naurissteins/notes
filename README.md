# Audio convert

### enc.pl
```
my ($width,$height) = ($vdata->{ID_VIDEO_WIDTH},$vdata->{ID_VIDEO_HEIGHT});
to
my ($width,$height) = ($vdata->{ID_AUDIO_CODEC},$vdata->{ID_AUDIO_CODEC});
``` 
 
```
$ffmpeg_string="$input_str $audio_str $video_str $flags -threads 0 $file_enc";
to
$ffmpeg_string="$input_str $audio_file -threads 0 $file_enc";
```

```
my $file_enc = "$c->{cgi_dir}/temp/$disk_id/$code\_$type.mp4";
to
my $file_enc = "$c->{cgi_dir}/temp/$disk_id/$code\_$type.mp3";
```

```
add new line after
my $video_str = "-c:v libx264 -preset $settings->{vid_preset} $fps_limit $enc_mode $videofilters";
my $audio_file = "-acodec libmp3lame -ac 2 -ab 96k -map a -map_metadata 0:s:0";
```

### fs.pm

```
$keep_orig=0 if $info_orig->{vid_height} <= $info_best->{vid_height};
to
$keep_orig=0 if $file->{file_spec_o}=~ /\.(mp3|flac|wav|acc|m4a|Audio)$/i;
```
