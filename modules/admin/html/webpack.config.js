import CssMinimizerPlugin from 'css-minimizer-webpack-plugin'
import HtmlWebPackPlugin from 'html-webpack-plugin'
import MiniCssExtractPlugin from 'mini-css-extract-plugin'
import HtmlInlineScriptPlugin from 'html-inline-script-webpack-plugin';

export default {
  entry: {
    index: './src/index.ts',
    connections: './src/connections.ts',
    requests: './src/requests.ts'
  },
  output: {
    filename: '[name].[contenthash].js',
    clean: true,
  },
  devtool: false,
  resolve: {
    extensions: ['.mjs', '.js', '.ts']
  },
  module: {
    rules: [
      {
        test: /\.css$/,
        use: [MiniCssExtractPlugin.loader, 'css-loader', 'postcss-loader']
      },
      {
        test: /\.ts$/,
        loader: 'ts-loader',
        options: { transpileOnly: true }
      }
    ]
  },
  optimization: {
    minimize: true,
    minimizer: ['...', new CssMinimizerPlugin()],
    usedExports: true,
  },
  plugins: [
    new HtmlWebPackPlugin({
      template: './src/index.ejs',
      filename: 'index.html',
      chunks: ['index'],
      inject: 'body',
      minify: {
        collapseWhitespace: true,
        removeComments: true,
        removeRedundantAttributes: true,
        useShortDoctype: true
      }
    }),
    new HtmlWebPackPlugin({
      template: './src/connections.ejs',
      filename: 'connections.html',
      chunks: ['connections'],
      inject: 'body',
      minify: {
        collapseWhitespace: true,
        removeComments: true,
        removeRedundantAttributes: true,
        useShortDoctype: true
      }
    }),
    new HtmlWebPackPlugin({
      template: './src/requests.ejs',
      filename: 'requests.html',
      chunks: ['requests'],
      inject: 'body',
      minify: {
        collapseWhitespace: true,
        removeComments: true,
        removeRedundantAttributes: true,
        useShortDoctype: true
      }
    }),
    new MiniCssExtractPlugin({ filename: '[contenthash].css' })
  ]
}

